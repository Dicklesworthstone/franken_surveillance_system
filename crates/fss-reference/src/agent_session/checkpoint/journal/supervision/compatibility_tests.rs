#![forbid(unsafe_code)]
//! Frozen unscheduled-v1 compatibility vectors, independent of the current encoder.
//!
//! These command bodies and hashes were calculated with Python's `struct`/`hashlib` from
//! commit 929a740a56a2524d5bf9a68328d04b9db0fb42d6: supervision.rs, its codec.rs, and the
//! fss-core canonical/anchor/ContractBasis layouts. Integers are big endian, text/bytes
//! carry u64 byte lengths, booleans/tags occupy one byte, and SHA-256 values carry tag 1.
//! No FSS encoder, digest/state implementation, or scheduled-supervision code generated
//! the vectors. Changing implementation and expected values together defeats this fixture.
//!
//! The codec test uses a fixed checkpoint identity. The replay test substitutes only the
//! enclosing session checkpoint identity so it can replay the frozen supervision history
//! inside a real admitted session without freezing unrelated session-checkpoint internals.
//! All command bodies, before/after supervision roots, reservations and deliveries stay fixed.

use std::collections::BTreeSet;

use fss_core::{
    AgentSession, AgentSessionParams, ContractBasis, ContractBasisRegistryBytes, MissionId,
};

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const PRINCIPAL: &str = "principal:legacy-compat";
const SESSION: &str = "session:legacy-compat";
const CONFIGURATION: &[u8] = br#"{"profile":"frozen unscheduled v1"}"#;
const PAYLOAD: &[u8] = br#"{"private":"synthetic frozen v1 report"}"#;
const AUTHORITY_HEX: &str = "1070a43f3e306a66483a02776e97f4e4d66b8a5e8e5f0ba394e769a05a8982cb";
const CHECKPOINT_HEX: &str = "7a935fdefc979c947de485ab3d02b2a37d8078b413b59c62b3ac7e4d41090c44";
const DESCRIPTOR_HEX: &str = "fdb0ea17100a6dd8f79e42fe52db072d477b4688b72faca31422a7a0a64986dc";

struct FrozenStep {
    name: &'static str,
    body: &'static str,
    record_digest: &'static str,
    before: &'static str,
    after: &'static str,
    state: &'static str,
    revision: u64,
    attempts: u32,
    reservation: Option<&'static str>,
    pending: Option<&'static str>,
    ack: Option<&'static str>,
    discard: Option<&'static str>,
}

fn digest_hex(hex: &str) -> TestResult<ContentDigest> {
    Ok(ContentDigest::parse(format!("sha256:{hex}"))?)
}

fn optional_hex(hex: Option<&str>) -> TestResult<Option<ContentDigest>> {
    hex.map(digest_hex).transpose()
}

fn hex_bytes(hex: &str) -> TestResult<Vec<u8>> {
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        return Err("invalid frozen v1 fixture hex".into());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

// A frozen header writer deliberately does not call CanonicalEncoder or codec::encode_record.
fn frozen_record(
    body: &str,
    checkpoint: ContentDigest,
    before: &str,
    after: &str,
) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for text in ["fss.reference_supervision_command.v1", PRINCIPAL, SESSION] {
        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    bytes.extend_from_slice(&10_i128.to_be_bytes());
    for digest in [checkpoint, digest_hex(before)?, digest_hex(after)?] {
        assert_eq!(digest.algorithm(), DigestAlgorithm::Sha256);
        bytes.push(1);
        bytes.extend_from_slice(&digest.bytes());
    }
    bytes.extend_from_slice(&hex_bytes(body)?);
    Ok(bytes)
}

fn fixture() -> TestResult<(ReferenceSessionStore, AgentSession)> {
    let basis = ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-reference:supervision-v1-compat",
    ));
    let anchor = LedgerAnchor {
        site_lineage: "site:legacy-compat".to_owned(),
        ledger_epoch: 3,
        commit_sequence: 5,
        adapter_registry_epoch: 7,
        schema_epoch: 11,
        policy_epoch: 13,
        privacy_epoch: 17,
        state_root: ContentDigest::sha256(b"frozen current authority root"),
    };
    let params = AgentSessionParams {
        session_id: SessionId::parse(SESSION)?,
        mission_id: MissionId::parse("mission:legacy-compat")?,
        principal_id: PrincipalId::parse(PRINCIPAL)?,
        capabilities: BTreeSet::from([
            "CAP-AGENT-SESSION-READ-001".to_owned(),
            "CAP-AGENT-SESSION-WRITE-001".to_owned(),
            "CAP-AGENT-SITUATION-READ-001".to_owned(),
            "CAP-AGENT-INVESTIGATE-001".to_owned(),
        ]),
        privacy_scope: BTreeSet::from(["private:property".to_owned()]),
        current_anchor: anchor,
        view_id: "AVIEW-001".to_owned(),
        token_budget: 100,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0,
        expires_at_ns: 1_000,
    };
    let mut memory = ReferenceSessionStore::default();
    let session = memory.open(params, basis, TimestampNs(10))?;
    Ok((memory, session))
}

fn replay_frozen_history(
    memory: &mut ReferenceSessionStore,
    state: &mut SupervisionState,
) -> TestResult {
    let limits = DurableSessionLimits::default();
    let checkpoint = memory.checkpoint(limits.max_checkpoint_bytes)?.digest();
    for step in STEPS {
        assert_eq!(state.digest(), digest_hex(step.before)?, "{} before", step.name);
        let bytes = frozen_record(step.body, checkpoint, step.before, step.after)?;
        replay_command(&bytes, memory, state, limits)?;
        assert_eq!(state.digest(), digest_hex(step.after)?, "{} after", step.name);
        let retained = state.retained();
        assert_eq!(retained.len(), 1, "{} inventory", step.name);
        let current = &retained[0];
        assert_eq!(current.digest(), digest_hex(step.state)?, "{} state", step.name);
        assert_eq!(current.authority_digest, digest_hex(AUTHORITY_HEX)?);
        assert_eq!(current.revision, step.revision);
        assert_eq!(current.attempts_reserved(), step.attempts);
        assert_eq!(current.reserved_bytes(), u64::from(step.attempts) * 10_000);
        assert_eq!(current.reserved_read_attempts(), u64::from(step.attempts) * 100);
        assert!(current.schedule.is_none(), "v1 history must not acquire a schedule");
        assert_eq!(current.registration().configuration.as_slice(), CONFIGURATION);
        assert_eq!(current.registration().maximum_attempts, 16);
        assert_eq!(current.registration().max_read_bytes, 10_000);
        assert_eq!(current.registration().max_read_attempts, 100);
        assert_eq!(current.reservation().map(SupervisionReservation::receipt), optional_hex(step.reservation)?);
        assert_eq!(current.pending().map(PendingSupervisionDelivery::receipt), optional_hex(step.pending)?);
        assert_eq!(current.last_acknowledged(), optional_hex(step.ack)?);
        assert_eq!(current.last_discarded(), optional_hex(step.discard)?);
        if let Some(pending) = current.pending() {
            assert!(pending.active_window_count.is_none());
            assert_eq!(pending.payload.as_slice(), PAYLOAD);
            assert_eq!(pending.payload_digest(), ContentDigest::sha256(PAYLOAD));
            let mut encoded = CanonicalEncoder::new();
            pending.encode_descriptor(&mut encoded);
            assert_eq!(ContentDigest::sha256(&encoded.finish()), digest_hex(DESCRIPTOR_HEX)?);
        }
        assert_eq!(memory.checkpoint(limits.max_checkpoint_bytes)?.digest(), checkpoint);
    }
    Ok(())
}

#[test]
fn frozen_v1_command_records_decode_and_reencode_byte_for_byte() -> TestResult {
    for step in STEPS {
        let bytes = frozen_record(step.body, digest_hex(CHECKPOINT_HEX)?, step.before, step.after)?;
        assert_eq!(ContentDigest::sha256(&bytes), digest_hex(step.record_digest)?, "{} frozen bytes", step.name);
        let decoded = codec::decode_record(&bytes)?;
        assert_eq!(decoded.principal.as_str(), PRINCIPAL);
        assert_eq!(decoded.session.as_str(), SESSION);
        assert_eq!(decoded.now, TimestampNs(10));
        assert_eq!(decoded.session_digest, digest_hex(CHECKPOINT_HEX)?);
        assert_eq!(decoded.before_state, digest_hex(step.before)?);
        assert_eq!(decoded.after_state, digest_hex(step.after)?);
        assert_eq!(codec::encode_record(&decoded)?, bytes, "{} wire compatibility", step.name);
    }
    Ok(())
}

#[test]
fn frozen_v1_history_preserves_unscheduled_state_and_all_delivery_receipts() -> TestResult {
    let (mut memory, _) = fixture()?;
    replay_frozen_history(&mut memory, &mut SupervisionState::default())
}

#[test]
fn frozen_v1_ack_without_reservation_remains_a_retry_and_never_a_history_transition() -> TestResult {
    let (mut memory, session) = fixture()?;
    let mut state = SupervisionState::default();
    replay_frozen_history(&mut memory, &mut state)?;
    let last = STEPS.last().ok_or("missing frozen history")?;
    let bytes = frozen_record(ACK_RETRY_BODY, digest_hex(CHECKPOINT_HEX)?, last.after, last.after)?;
    assert_eq!(ContentDigest::sha256(&bytes), digest_hex(ACK_RETRY_RECORD_HEX)?);
    let decoded = codec::decode_record(&bytes)?;
    assert!(matches!(&decoded.command, Command::Acknowledge { reservation: None, .. }));
    assert_eq!(codec::encode_record(&decoded)?, bytes);
    let before = state.retained();
    let retried = apply(
        &mut memory, &mut state, &session.principal_id, &session.session_id,
        &decoded.command, TimestampNs(10),
    )?;
    assert_eq!(state.retained(), before);
    assert_eq!(retried, before[0]);
    assert_eq!(retried.attempts_reserved(), 4);
    assert_eq!(retried.last_discarded(), optional_hex(last.discard)?);
    let limits = DurableSessionLimits::default();
    let checkpoint = memory.checkpoint(limits.max_checkpoint_bytes)?.digest();
    let bytes = frozen_record(ACK_RETRY_BODY, checkpoint, last.after, last.after)?;
    assert!(matches!(
        replay_command(&bytes, &mut memory, &mut state, limits),
        Err(DurableSessionError::InvalidHistory)
    ));
    assert_eq!(state.retained(), before);
    Ok(())
}

// Literal frozen-v1 command bodies and independent SHA-256/state/receipt vectors follow.

const STEPS: &[FrozenStep] = &[
    FrozenStep {
        name: "register",
        body: concat!(
            "00000000000000001573657373696f6e3a6c65676163792d636f6d706174000000000000000966726f7a656e2d763100",
            "000000000000237b2270726f66696c65223a2266726f7a656e20756e7363686564756c6564207631227d012ab694569e",
            "2643b19a13324726c8b5f6c7337e4320a9dc03d8e2fc83d6818846000000000000271000000000000000640000001000",
            "00000000001000",
        ),
        record_digest: "2d459b30d6ebfb564fa3125db13b0f7cca27ae47d1313de289f1d9671a371502",
        before: "b04c4d579d4000547f886976b8ee63e2a20199090aee8fe4ce79418f1ab08af8",
        after: "c0e295653f0d91588f1683ec158c47970707284efb6954a34e8578979bfd1056",
        state: "28df9d9c7d5e72a8280be38941b08106c597f08932509a8ebdf3aff099843b15",
        revision: 0,
        attempts: 0,
        reservation: None,
        pending: None,
        ack: None,
        discard: None,
    },
    FrozenStep {
        name: "reserve_analysis",
        body: concat!(
            "01000000000000000966726f7a656e2d76310128df9d9c7d5e72a8280be38941b08106c597f08932509a8ebdf3aff099",
            "843b150000000000000012736974653a6c65676163792d636f6d70617400000000000000030000000000000005000000",
            "0000000007000000000000000b000000000000000d000000000000001101745ca5a08c1edfc6333893fbfec5d2eda168",
            "518d51f5f89c8d27d106e79cc56c",
        ),
        record_digest: "d6bfd905e60430d45682bd9bee1b11f2aba7972a85a9fce5ffef255aa551ace1",
        before: "c0e295653f0d91588f1683ec158c47970707284efb6954a34e8578979bfd1056",
        after: "301ede1cdae3b96b8cc7875bf3ba0cb412e739f8d3f234c978b3dc89427706d5",
        state: "8f0428ffa8809a131cbb4ec267d43db39a02bac170c503021896b50087e15681",
        revision: 1,
        attempts: 1,
        reservation: Some("f70396863ed1cac4652cc0dfa3e064fba17d0dfa62423df3628c6dd2fe345ae0"),
        pending: None,
        ack: None,
        discard: None,
    },
    FrozenStep {
        name: "publish_first",
        body: concat!(
            "02000000000000000966726f7a656e2d7631018f0428ffa8809a131cbb4ec267d43db39a02bac170c503021896b50087",
            "e1568101f70396863ed1cac4652cc0dfa3e064fba17d0dfa62423df3628c6dd2fe345ae000000000000000287b227072",
            "6976617465223a2273796e7468657469632066726f7a656e207631207265706f7274227d000000000000000200000000",
            "000000166576656e743a7061636b6167653a6d657461646174610139556e8664051dda4ed045c4ebcaeaf4a121089db3",
            "40e9a4c4fb02f4637fef670000000000000000146576656e743a7061636b6167653a6e617469766501b0b9a975666488",
            "dc7b1b0ea74df270f198de8495437a83f8a144a90d3d22ce120101d248ced836dc301af294d3811161d0ab365b824f2f",
            "bcb8c1c26d3b0d7352fd0a",
        ),
        record_digest: "0c03e7e0928bf28c539ef0908ba39286d1ea50505cdb5cf06e8b067fdc891953",
        before: "301ede1cdae3b96b8cc7875bf3ba0cb412e739f8d3f234c978b3dc89427706d5",
        after: "a7f66059e70b2a598c196c2a313da30aac5df92ff6bf7bcf95606cdb2fd6e0fe",
        state: "3f5a3fe5f3ff496d5324ea9240cd94be2ec3a91c3ce4ec90472ae059d887fcac",
        revision: 2,
        attempts: 1,
        reservation: None,
        pending: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        ack: None,
        discard: None,
    },
    FrozenStep {
        name: "reserve_release",
        body: concat!(
            "01000000000000000966726f7a656e2d7631013f5a3fe5f3ff496d5324ea9240cd94be2ec3a91c3ce4ec90472ae059d8",
            "87fcac0000000000000012736974653a6c65676163792d636f6d70617400000000000000030000000000000005000000",
            "0000000007000000000000000b000000000000000d000000000000001101745ca5a08c1edfc6333893fbfec5d2eda168",
            "518d51f5f89c8d27d106e79cc56c",
        ),
        record_digest: "65ae07ff162c246618b75b4db5f01be68dac3a672dd7acbef270752e7b6f1d64",
        before: "a7f66059e70b2a598c196c2a313da30aac5df92ff6bf7bcf95606cdb2fd6e0fe",
        after: "7ebad42ffaf3a6b50b2be08a49b898137b75873349c9d501fcca0a2cacddfab8",
        state: "01a1fd61d4639a226213778d6ae151f21ce0969ef7effa0495059e57aba36ff6",
        revision: 3,
        attempts: 2,
        reservation: Some("72fa46e5ebbebe4a91e0d01d8d652e7301e29c2542a99bd955e5defe362ac055"),
        pending: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        ack: None,
        discard: None,
    },
    FrozenStep {
        name: "release",
        body: concat!(
            "03000000000000000966726f7a656e2d76310101a1fd61d4639a226213778d6ae151f21ce0969ef7effa0495059e57ab",
            "a36ff60172fa46e5ebbebe4a91e0d01d8d652e7301e29c2542a99bd955e5defe362ac05501505ab07b7dce3eeb3d76e2",
            "ec52ce90906bcfaa7de2db13a57d5d8c3155783637",
        ),
        record_digest: "19f2e4d52efce319829e509291e421027e00fb4e2c566672299492528604f469",
        before: "7ebad42ffaf3a6b50b2be08a49b898137b75873349c9d501fcca0a2cacddfab8",
        after: "17cc1611099bfe0e2768cd69796986e704b3006e8fb6f0ba64595750f57f69b3",
        state: "eefb2f14590bf52d76cae584ddc67da9a77eea560329efa113a8cc99aa9a3e0b",
        revision: 4,
        attempts: 2,
        reservation: None,
        pending: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        ack: None,
        discard: None,
    },
    FrozenStep {
        name: "reserve_ack",
        body: concat!(
            "01000000000000000966726f7a656e2d763101eefb2f14590bf52d76cae584ddc67da9a77eea560329efa113a8cc99aa",
            "9a3e0b0000000000000012736974653a6c65676163792d636f6d70617400000000000000030000000000000005000000",
            "0000000007000000000000000b000000000000000d000000000000001101745ca5a08c1edfc6333893fbfec5d2eda168",
            "518d51f5f89c8d27d106e79cc56c",
        ),
        record_digest: "84729adc131dbf27425c87e4c19d0b4e7a28536ce03f4df1673925022022660d",
        before: "17cc1611099bfe0e2768cd69796986e704b3006e8fb6f0ba64595750f57f69b3",
        after: "fa0c7e5b5a9197fa5cf678ce41446fb89171cdcf6b22667b5b101c308ca9c2f7",
        state: "99208fa8004cde69a9f97d8ae98bc4957706ae2b2c471a2a9e63908c36d8ca0e",
        revision: 5,
        attempts: 3,
        reservation: Some("040c4aea3e98306314a4b964c322764bab418fc7bd84afeb95a4fdd1f03c0321"),
        pending: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        ack: None,
        discard: None,
    },
    FrozenStep {
        name: "acknowledge",
        body: concat!(
            "04000000000000000966726f7a656e2d76310199208fa8004cde69a9f97d8ae98bc4957706ae2b2c471a2a9e63908c36",
            "d8ca0e0101040c4aea3e98306314a4b964c322764bab418fc7bd84afeb95a4fdd1f03c032101505ab07b7dce3eeb3d76",
            "e2ec52ce90906bcfaa7de2db13a57d5d8c31557836370000000000000012736974653a6c65676163792d636f6d706174",
            "000000000000000300000000000000050000000000000007000000000000000b000000000000000d0000000000000011",
            "01745ca5a08c1edfc6333893fbfec5d2eda168518d51f5f89c8d27d106e79cc56c",
        ),
        record_digest: "20086ca673df83209836a3a88c842151b8a8e24685033a6760f96faa1aaaf7c8",
        before: "fa0c7e5b5a9197fa5cf678ce41446fb89171cdcf6b22667b5b101c308ca9c2f7",
        after: "52a179c2b5c3cb99edbcb65dfca5ff025507bb11e15f53a4bf0ef7b89aba94ec",
        state: "0d9073fe1817211881f3d5d0c3f2c83ca888e7ff925c880764c2cba737030da9",
        revision: 6,
        attempts: 3,
        reservation: None,
        pending: None,
        ack: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        discard: None,
    },
    FrozenStep {
        name: "reserve_successor",
        body: concat!(
            "01000000000000000966726f7a656e2d7631010d9073fe1817211881f3d5d0c3f2c83ca888e7ff925c880764c2cba737",
            "030da90000000000000012736974653a6c65676163792d636f6d70617400000000000000030000000000000005000000",
            "0000000007000000000000000b000000000000000d000000000000001101745ca5a08c1edfc6333893fbfec5d2eda168",
            "518d51f5f89c8d27d106e79cc56c",
        ),
        record_digest: "5409e2c343a068e8e1a7a6a9a4e4246974c1b68292bf72c7d5f2804600a18ba3",
        before: "52a179c2b5c3cb99edbcb65dfca5ff025507bb11e15f53a4bf0ef7b89aba94ec",
        after: "5107b0c7a8e62ba79c9e8543e3b4e22436be832d2aaca1683b5d683572e048dc",
        state: "06102e85a5742b1ebe046062ddda451a73ad996ebee0680d5bb11fb88b9d7bf6",
        revision: 7,
        attempts: 4,
        reservation: Some("2fb9fa0068a6ada55bf772c9e1d3b451b505c1fafba26b889396665fa4bd53e7"),
        pending: None,
        ack: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        discard: None,
    },
    FrozenStep {
        name: "publish_successor",
        body: concat!(
            "02000000000000000966726f7a656e2d76310106102e85a5742b1ebe046062ddda451a73ad996ebee0680d5bb11fb88b",
            "9d7bf6012fb9fa0068a6ada55bf772c9e1d3b451b505c1fafba26b889396665fa4bd53e700000000000000287b227072",
            "6976617465223a2273796e7468657469632066726f7a656e207631207265706f7274227d000000000000000200000000",
            "000000166576656e743a7061636b6167653a6d657461646174610139556e8664051dda4ed045c4ebcaeaf4a121089db3",
            "40e9a4c4fb02f4637fef670000000000000000146576656e743a7061636b6167653a6e617469766501b0b9a975666488",
            "dc7b1b0ea74df270f198de8495437a83f8a144a90d3d22ce120101d248ced836dc301af294d3811161d0ab365b824f2f",
            "bcb8c1c26d3b0d7352fd0a",
        ),
        record_digest: "7aaa21c5dc544a3ff29bb252eae3e9185b56614c532485dcaec5803cdcbe568b",
        before: "5107b0c7a8e62ba79c9e8543e3b4e22436be832d2aaca1683b5d683572e048dc",
        after: "2a86b4371c32225f3fe31a048b2773d4e06f8441a153f759e97b724d63f06f40",
        state: "4dc2d3b68b276e1958ed6f36e641e2811538aa8f9dae4ad0ded62146656cf2d9",
        revision: 8,
        attempts: 4,
        reservation: None,
        pending: Some("42e645b81e95d1a6c7013abe4d6b62c2360ec4d1ee642deea1961c13f0028f11"),
        ack: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        discard: None,
    },
    FrozenStep {
        name: "discard",
        body: concat!(
            "05000000000000000966726f7a656e2d7631014dc2d3b68b276e1958ed6f36e641e2811538aa8f9dae4ad0ded6214665",
            "6cf2d90142e645b81e95d1a6c7013abe4d6b62c2360ec4d1ee642deea1961c13f0028f11000000000000001273697465",
            "3a6c65676163792d636f6d706174000000000000000300000000000000050000000000000007000000000000000b0000",
            "00000000000d000000000000001101745ca5a08c1edfc6333893fbfec5d2eda168518d51f5f89c8d27d106e79cc56c",
        ),
        record_digest: "0d7091a4a184b806d47404b658c1f239e0c7cd1e3baa8bbc0633ef32dcadce8c",
        before: "2a86b4371c32225f3fe31a048b2773d4e06f8441a153f759e97b724d63f06f40",
        after: "e7aae07c98b30c6953ebe9ffa8a5f5f1d9a32083dcdc7d7579af1cf4b62f65fc",
        state: "7141ec73be966a0dcd96c81023b42ca936880f5896c8f146b7c83577da3a19df",
        revision: 9,
        attempts: 4,
        reservation: None,
        pending: None,
        ack: Some("505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c3155783637"),
        discard: Some("42e645b81e95d1a6c7013abe4d6b62c2360ec4d1ee642deea1961c13f0028f11"),
    },
];

const ACK_RETRY_BODY: &str = concat!(
    "04000000000000000966726f7a656e2d7631017141ec73be966a0dcd96c81023b42ca936880f5896c8f146b7c83577da",
    "3a19df0001505ab07b7dce3eeb3d76e2ec52ce90906bcfaa7de2db13a57d5d8c31557836370000000000000012736974",
    "653a6c65676163792d636f6d706174000000000000000300000000000000050000000000000007000000000000000b00",
    "0000000000000d000000000000001101745ca5a08c1edfc6333893fbfec5d2eda168518d51f5f89c8d27d106e79cc56c",
);
const ACK_RETRY_RECORD_HEX: &str = "e232f7a88659cae1fe2faddb9a0da358cd6eb15deddd298003fbb1fcf0cc57b7";
