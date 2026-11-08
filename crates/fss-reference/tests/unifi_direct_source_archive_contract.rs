#![forbid(unsafe_code)]
//! Standalone source publication, recovery, and retention-authority contracts.

use std::{cell::Cell, error::Error, path::PathBuf, sync::Arc};

use fss_container::flv_avc::SourceKey;
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RootAuthoritySpec, region::ContextAuthority,
};
use fss_geometry::WorkBudget;
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_packet::extended_flv::{
    Limits as FlvLimits,
    stream::{Framer, Next, RecordKind, SearchMode, SourceRecord},
};
use fss_reference::{
    ReferenceDeployment, ReplayCx,
    unifi_direct::{archive, recording::SourceDisposition, source_evidence},
};

type Test = Result<(), Box<dyn Error>>;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Access(Cell<bool>);
struct Cutoff {
    calls: Cell<usize>,
    allow: usize,
}
impl archive::RetainAuthority for Cutoff {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        n <= self.allow
    }
}
impl archive::RetainAuthority for Access {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        self.0.get()
    }
}
impl archive::ReadAuthority for Access {
    fn permits(&self, _: ContentDigest, _: ContentDigest) -> bool {
        self.0.get()
    }
}

fn header() -> Result<SourceRecord, Box<dyn Error>> {
    let mut framer = Framer::new(FlvLimits::default(), 1024)?;
    framer.append(0, b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00")?;
    match framer.take()? {
        Next::Record(record) => Ok(record),
        Next::NeedMore => Err("header missing".into()),
    }
}

fn tag(kind: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = vec![
        kind,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
        (timestamp >> 16) as u8,
        (timestamp >> 8) as u8,
        timestamp as u8,
        (timestamp >> 24) as u8,
        0,
        0,
        0,
    ];
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11_u32 + n as u32).to_be_bytes());
    out
}

fn provisional_record() -> Result<SourceRecord, Box<dyn Error>> {
    let limits = FlvLimits {
        max_payload: 64,
        max_trailer: 64,
        ..FlvLimits::default()
    };
    let mut framer = Framer::with_mode(limits, 128, SearchMode::Provisional)?;
    let mut first = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    first.extend_from_slice(&tag(9, 0, b"first"));
    framer.append(0, &first)?;
    assert!(matches!(framer.take()?, Next::Record(_)));
    assert!(matches!(framer.take()?, Next::Record(_)));
    let embedded = tag(8, 1, b"audio");
    let mut payload = embedded.clone();
    payload.resize(40, 0x77);
    let outer = tag(9, 2, &payload);
    framer.append(framer.next_offset(), &outer[..11 + embedded.len()])?;
    match framer.take()? {
        Next::Record(record) => Ok(record),
        Next::NeedMore => Err("provisional record missing".into()),
    }
}

#[test]
fn standalone_source_denial_retry_and_cold_read_preserve_exact_bytes() -> Test {
    let source = header()?;
    let key = SourceKey {
        connection: 1,
        generation: 2,
    };
    let camera = ContentDigest::sha256(b"fixture camera claim");
    let retention = ContentDigest::sha256(b"fixture source retention");
    let plan = source_evidence::Prepared::new(
        &source,
        key,
        SourceDisposition::Header,
        camera,
        retention,
        1024,
    )?;
    let other = source_evidence::Prepared::new(
        &source,
        SourceKey {
            connection: 3,
            generation: 2,
        },
        SourceDisposition::Header,
        camera,
        retention,
        1024,
    )?;
    let pin = archive::UnknownTimePin::from_source_plan(&plan);
    assert_ne!(pin, archive::UnknownTimePin::from_source_plan(&other));
    assert!(
        source_evidence::Prepared::new(
            &source,
            key,
            SourceDisposition::PreRoll,
            camera,
            retention,
            1024
        )
        .is_err()
    );
    assert!(
        source_evidence::Prepared::new(
            &source,
            key,
            SourceDisposition::Header,
            camera,
            retention,
            12
        )
        .is_err()
    );
    let temp =
        Temp(std::env::temp_dir().join(format!("fss-unifi-source-archive-{}", std::process::id())));
    std::fs::create_dir(&temp.0)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:source-archive".into(),
        operation_id: OperationId::parse("operation:source-archive")?,
        principal: "principal:fixture".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 1,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(10_000)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:source-archive"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, temp.0.clone())?;
    let target = temp.0.join("deployment");
    let journal_path = temp.0.join("journal");
    let keeper_path = temp.0.join("keeper");
    let scope = ContentDigest::sha256(b"fixture dedicated source scope");
    let store = FileEffectJournal::create(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut journal = archive::journal::UnknownTimeJournal::create(Box::new(store), scope, &cx)?;
    let store = FileEffectJournal::create(
        &keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut keeper =
        archive::journal::UnknownTimeAnchorKeeper::create(Box::new(store), &journal, &cx)?;
    let mut deployment = ReferenceDeployment::open(&target, "site:source-archive", &cx)?;
    let access = Access(Cell::new(false));
    let publish = |plan: &source_evidence::Prepared<'_>,
                   deployment: &mut ReferenceDeployment,
                   journal: &mut archive::journal::UnknownTimeJournal,
                   keeper: &mut archive::journal::UnknownTimeAnchorKeeper| {
        archive::publish_unknown_time_source_anchored(
            plan,
            deployment,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            journal,
            keeper,
        )
    };
    assert!(matches!(
        publish(&plan, &mut deployment, &mut journal, &mut keeper),
        Err(archive::UnknownTimePublishError::Archive(
            archive::Error::Denied
        ))
    ));
    assert_eq!(journal.pending(), Some(pin));
    assert!(matches!(
        publish(&other, &mut deployment, &mut journal, &mut keeper),
        Err(archive::UnknownTimePublishError::Candidate)
    ));
    assert_eq!(
        source.bytes(),
        b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00"
    );
    access.0.set(true);
    let receipt = publish(&plan, &mut deployment, &mut journal, &mut keeper)?;
    assert_eq!(receipt.root, pin.root);
    assert_eq!(journal.confirmed(), Some(pin));
    assert_eq!(keeper.target(), journal.anchor());
    let journal_anchor = journal.anchor();
    let keeper_anchor = keeper.anchor();
    let source_offset = source.offset();
    let source_kind = source.kind();
    drop(other);
    drop(plan);
    drop(source);
    drop(keeper);
    drop(journal);
    drop(deployment);
    let store = FileEffectJournal::open(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        journal_anchor,
    )?;
    let mut journal =
        archive::journal::UnknownTimeJournal::reopen(Box::new(store), scope, journal_anchor, &cx)?;
    let store = FileEffectJournal::open(
        &keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        keeper_anchor,
    )?;
    let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
        Box::new(store),
        &journal,
        keeper_anchor,
        &cx,
    )?;
    assert_eq!(journal.confirmed(), Some(pin));
    assert_eq!(keeper.target(), journal.anchor());
    let mut deployment = ReferenceDeployment::open(&target, "site:source-archive", &cx)?;
    access.0.set(false);
    assert!(matches!(
        archive::read_unknown_time_source(
            &mut deployment,
            pin,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    access.0.set(true);
    let recovered = archive::read_unknown_time_source(
        &mut deployment,
        pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        recovered.publication_state(),
        archive::SourcePublicationState::Ledgered
    );
    assert_eq!(
        (
            recovered.key(),
            recovered.camera_claim(),
            recovered.disposition(),
            recovered.offset(),
            recovered.kind()
        ),
        (
            key,
            camera,
            SourceDisposition::Header,
            source_offset,
            source_kind
        )
    );
    assert_eq!(
        recovered.bytes(),
        b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00"
    );
    let forged = archive::UnknownTimePin {
        root: pin.root,
        retention: ContentDigest::sha256(b"different retention"),
    };
    assert!(matches!(
        archive::read_unknown_time_source(
            &mut deployment,
            forged,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Mismatch)
    ));
    assert_eq!(journal.replay_pin(), Some(pin));
    let replay_plan = source_evidence::Prepared::from_recovered(&recovered);
    assert_eq!(archive::UnknownTimePin::from_source_plan(&replay_plan), pin);
    assert_eq!(
        publish(&replay_plan, &mut deployment, &mut journal, &mut keeper)?.root,
        pin.root
    );
    assert_eq!(journal.replay_pin(), None);
    let mut wire = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
    wire.extend_from_slice(&[9, 0, 0, 1, 0, 0, 42, 0, 0, 0, 0, 0x17, 0, 0, 0, 12]);
    let mut framer = Framer::new(FlvLimits::default(), 1024)?;
    framer.append(0, &wire)?;
    assert!(matches!(framer.take()?, Next::Record(_)));
    let tag = match framer.take()? {
        Next::Record(record) => record,
        Next::NeedMore => return Err("first tag missing".into()),
    };
    let second = source_evidence::Prepared::new(
        &tag,
        key,
        SourceDisposition::PreRoll,
        camera,
        retention,
        1024,
    )?;
    let second_pin = archive::UnknownTimePin::from_source_plan(&second);
    assert_ne!(pin, second_pin);
    let second_receipt = publish(&second, &mut deployment, &mut journal, &mut keeper)?;
    assert_eq!(second_receipt.root, second_pin.root);
    assert_eq!(journal.confirmed(), Some(second_pin));
    let recovered = archive::read_unknown_time_source(
        &mut deployment,
        second_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        (
            recovered.key(),
            recovered.disposition(),
            recovered.offset(),
            recovered.kind()
        ),
        (key, SourceDisposition::PreRoll, tag.offset(), tag.kind())
    );
    assert_eq!(recovered.bytes(), tag.bytes());
    let provisional = provisional_record()?;
    assert!(matches!(
        provisional.kind(),
        RecordKind::Candidate {
            provisional: true,
            earlier_incomplete: true,
            ..
        }
    ));
    let third = source_evidence::Prepared::new(
        &provisional,
        key,
        SourceDisposition::PreRoll,
        camera,
        retention,
        1024,
    )?;
    let third_pin = archive::UnknownTimePin::from_source_plan(&third);
    assert_eq!(
        publish(&third, &mut deployment, &mut journal, &mut keeper)?.root,
        third_pin.root
    );
    let recovered = archive::read_unknown_time_source(
        &mut deployment,
        third_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        (recovered.offset(), recovered.kind()),
        (provisional.offset(), provisional.kind())
    );
    assert_eq!(recovered.bytes(), provisional.bytes());
    let staged_key = SourceKey {
        connection: 4,
        generation: 2,
    };
    let staged_plan = source_evidence::Prepared::new(
        &tag,
        staged_key,
        SourceDisposition::PreRoll,
        camera,
        retention,
        1024,
    )?;
    let staged_pin = archive::UnknownTimePin::from_source_plan(&staged_plan);
    let cutoff = Cutoff {
        calls: Cell::new(0),
        allow: 4,
    };
    assert!(matches!(
        archive::publish_unknown_time_source_anchored(
            &staged_plan,
            &mut deployment,
            &cutoff,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx,
            &mut journal,
            &mut keeper
        ),
        Err(archive::UnknownTimePublishError::Archive(
            archive::Error::Denied
        ))
    ));
    assert_eq!(cutoff.calls.get(), 5);
    assert_eq!(journal.pending(), Some(staged_pin));
    assert_eq!(keeper.target(), journal.anchor());
    let staged_offset = tag.offset();
    let staged_kind = tag.kind();
    let journal_anchor = journal.anchor();
    let keeper_anchor = keeper.anchor();
    drop(staged_plan);
    drop(second);
    drop(tag);
    drop(keeper);
    drop(journal);
    drop(deployment);
    let store = FileEffectJournal::open(
        &journal_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        journal_anchor,
    )?;
    let mut journal =
        archive::journal::UnknownTimeJournal::reopen(Box::new(store), scope, journal_anchor, &cx)?;
    let store = FileEffectJournal::open(
        &keeper_path,
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        keeper_anchor,
    )?;
    let mut keeper = archive::journal::UnknownTimeAnchorKeeper::reopen(
        Box::new(store),
        &journal,
        keeper_anchor,
        &cx,
    )?;
    let mut deployment = ReferenceDeployment::open(&target, "site:source-archive", &cx)?;
    access.0.set(false);
    assert!(matches!(
        archive::read_staged_unknown_time_source(
            &deployment,
            &journal,
            &keeper,
            &access,
            archive::Limits::default(),
            &mut WorkBudget::new(4_000_000_000),
            &cx
        ),
        Err(archive::Error::Denied)
    ));
    access.0.set(true);
    let staged = archive::read_staged_unknown_time_source(
        &deployment,
        &journal,
        &keeper,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        staged.publication_state(),
        archive::SourcePublicationState::Staged
    );
    assert_eq!(
        (staged.key(), staged.offset(), staged.kind()),
        (staged_key, staged_offset, staged_kind)
    );
    assert_eq!(
        staged.bytes(),
        &[9, 0, 0, 1, 0, 0, 42, 0, 0, 0, 0, 0x17, 0, 0, 0, 12]
    );
    let staged_replay = source_evidence::Prepared::from_recovered(&staged);
    assert_eq!(
        archive::UnknownTimePin::from_source_plan(&staged_replay),
        staged_pin
    );
    assert_eq!(
        publish(&staged_replay, &mut deployment, &mut journal, &mut keeper)?.root,
        staged_pin.root
    );
    let ledgered = archive::read_unknown_time_source(
        &mut deployment,
        staged_pin,
        &access,
        archive::Limits::default(),
        &mut WorkBudget::new(4_000_000_000),
        &cx,
    )?;
    assert_eq!(
        ledgered.publication_state(),
        archive::SourcePublicationState::Ledgered
    );
    assert_eq!(ledgered.bytes(), staged.bytes());
    Ok(())
}
