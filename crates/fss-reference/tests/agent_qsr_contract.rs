#![forbid(unsafe_code)]
//! Canonical QSR query admission and immutable native-source parity.

mod qsr_observations_support;

use std::collections::BTreeSet;
use std::fs;
use std::sync::atomic::{AtomicI64, Ordering};

use fss_core::json_input;
use fss_core::{
    CanonicalEncoder, ContentDigest, ContextAuthority, OperationId, PrincipalId, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_reference::ReferenceDeployment;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_qsr::{
    QsrQueryError, QsrQueryLimits, QsrQueryRequest, QsrSourceReadPermit, query_qsr_in_deployment,
};
use fss_reference::ingest::qsr_observations::QsrZoneRole;
use qsr_observations_support::{Directory, Fixture, PRINCIPAL, SITE, Test, config, context};

fn request(report_digest: ContentDigest) -> Test<QsrQueryRequest> {
    Ok(QsrQueryRequest {
        report_digest,
        config: config(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        expected_anchor: None,
    })
}

fn authority_spec(request: &QsrQueryRequest, limits: QsrQueryLimits) -> Test<RootAuthoritySpec> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:canonical-qsr-contract".into(),
        operation_id: OperationId::parse("operation:canonical-qsr-contract")?,
        principal: request.principal.as_str().to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            RuntimeGrant::AgentQuery.as_str().into(),
            RuntimeGrant::ReadMedia.as_str().into(),
        ],
        deadline: None,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: request.report_digest,
        generation: 1,
    })
}

#[test]
fn canonical_query_preserves_native_bytes_identities_complete_rows_and_unresolved_effects() -> Test
{
    let fixture = Fixture::new("agent-qsr-native-parity")?;
    let before = fixture.source.journals()?;
    let temporary = fixture
        .source
        .root
        .join("LAYOUT.tmp.agent-qsr-must-preserve");
    fs::write(
        &temporary,
        b"immutable canonical reads do not recover local state",
    )?;
    let request = request(fixture.report)?;
    let limits = QsrQueryLimits::default();
    let authority = ContextAuthority::new_root(authority_spec(&request, limits)?)?;
    let now = || TimestampNs(0);
    let permit =
        QsrSourceReadPermit::authorize(&authority, &fixture.source.root, &request, limits, &now)?;
    let query = query_qsr_in_deployment(
        &fixture.source.root,
        &request,
        limits,
        Some(&permit),
        &|| false,
    )?;
    assert_eq!(query.report.encoded(), fixture.expected_bytes);
    assert_eq!(query.report.to_json()?, fixture.expected_json);
    assert_eq!(
        query.report.digest(),
        ContentDigest::sha256(&fixture.expected_bytes)
    );
    assert_eq!(query.source_permit_digest, permit.digest());
    assert!(query.read_usage.read_bytes > 0);
    assert!(query.read_usage.read_objects > 0);
    assert!(query.read_usage.read_bytes <= limits.read.max_read_bytes as u64);
    assert!(query.read_usage.read_objects <= limits.read.max_read_objects as u64);
    assert_eq!(query.coverage().omitted_count, 0);
    assert!(
        query
            .coverage()
            .not_observable_domain
            .iter()
            .any(|entry| entry.contains("physical identity"))
    );

    let native = json_input::parse(&fixture.expected_json)?;
    let native = native.object().ok_or("native object")?;
    let expected_handles = vec![
        query.report.digest().to_text(),
        query.report.source().digest().to_text(),
        query.report.source().provenance_root().to_text(),
    ];
    let companion = json_input::parse(query.report.lane_traversals().to_json())?;
    let companion = companion.object().ok_or("companion object")?;
    let companion_handles = vec![
        query.report.lane_traversals().digest().to_text(),
        query.report.digest().to_text(),
        query.report.source().digest().to_text(),
        query.report.source().provenance_root().to_text(),
    ];
    assert_eq!(
        query.report.lane_traversals().digest(),
        ContentDigest::sha256(query.report.lane_traversals().encoded())
    );
    assert_eq!(
        companion
            .get("source_qsr_report")
            .and_then(|value| value.text()),
        Some(query.report.digest().to_text().as_str())
    );
    let mut identities = BTreeSet::new();
    for proposition in &query.epistemic.propositions {
        assert!(
            identities.insert(&proposition.id),
            "duplicate projected row"
        );
        assert_eq!(proposition.provenance, "derived");
        let (selected, handles, row) = if let Some(row) = proposition.id.strip_prefix("claim:qsr:")
        {
            (native, &expected_handles, row)
        } else {
            (
                companion,
                &companion_handles,
                proposition
                    .id
                    .strip_prefix("claim:qsr-lane:")
                    .ok_or("QSR companion identity")?,
            )
        };
        assert_eq!(&proposition.evidence, handles);
        assert!(
            !proposition
                .statement
                .contains(fixture.source.root.to_str().ok_or("root")?)
        );
        let encoded = proposition
            .statement
            .split_once(": ")
            .ok_or("native row value")?
            .1;
        let value = json_input::parse(encoded)?;
        match row.split_once(':') {
            Some((section, ordinal)) => {
                let ordinal: usize = ordinal.parse()?;
                let expected = selected
                    .get(section)
                    .and_then(|value| value.array())
                    .and_then(|values| values.get(ordinal))
                    .ok_or("native array row")?;
                assert_eq!(&value, expected);
            }
            None => assert_eq!(Some(&value), selected.get(row)),
        }
    }
    let expected_rows: usize = native
        .values()
        .map(|value| value.array().map_or(1, |rows| rows.len().max(1)))
        .sum();
    let companion_rows = companion.len() - 1
        + companion
            .get("traversals")
            .and_then(|value| value.array())
            .ok_or("traversals")?
            .len()
            .max(1);
    assert_eq!(
        query.epistemic.propositions.len(),
        expected_rows + companion_rows
    );
    let mut decision = CanonicalEncoder::new();
    decision.text("fss.agent_qsr_query.lane_decision.v1");
    decision.digest(query.request_digest);
    decision.digest(query.report.digest());
    decision.digest(query.report.lane_traversals().digest());
    decision.digest(query.plan.plan_digest());
    assert_eq!(
        query.decision_digest,
        ContentDigest::sha256(&decision.finish_checked()?)
    );
    assert_eq!(fixture.source.journals()?, before);
    assert_eq!(
        fs::read(&temporary)?,
        b"immutable canonical reads do not recover local state"
    );
    Ok(())
}

#[test]
fn missing_or_mismatched_source_permits_refuse_before_touching_an_absent_root() -> Test {
    let directory = Directory::new("agent-qsr-grant-binding")?;
    let root = directory.0.join("absent");
    let request = request(ContentDigest::sha256(b"exact retained QSR request"))?;
    let limits = QsrQueryLimits::default();
    let authority = ContextAuthority::new_root(authority_spec(&request, limits)?)?;
    let now = || TimestampNs(0);
    assert!(matches!(
        query_qsr_in_deployment(&root, &request, limits, None, &|| false),
        Err(QsrQueryError::Unauthorized)
    ));
    let permit = QsrSourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    let other = directory.0.join("another-absent-root");
    assert!(matches!(
        query_qsr_in_deployment(&other, &request, limits, Some(&permit), &|| false),
        Err(QsrQueryError::Unauthorized)
    ));
    for change in 0..3 {
        let mut altered = request.clone();
        match change {
            0 => altered.report_digest = ContentDigest::sha256(b"different retained report"),
            1 => altered.principal = PrincipalId::parse("principal:another-operator")?,
            _ => altered.config.zone_roles[0].role = QsrZoneRole::Area,
        }
        assert!(matches!(
            query_qsr_in_deployment(&root, &altered, limits, Some(&permit), &|| false),
            Err(QsrQueryError::Unauthorized)
        ));
    }
    let mut altered_limits = limits;
    altered_limits.read.max_read_bytes -= 1;
    assert!(matches!(
        query_qsr_in_deployment(&root, &request, altered_limits, Some(&permit), &|| false),
        Err(QsrQueryError::Unauthorized)
    ));
    assert!(!root.exists());
    assert!(!other.exists());
    assert!(fs::read_dir(&directory.0)?.next().is_none());
    Ok(())
}

#[test]
fn every_required_source_grant_and_exact_context_binding_is_admitted_before_io() -> Test {
    let directory = Directory::new("agent-qsr-capabilities")?;
    let root = directory.0.join("absent");
    let request = request(ContentDigest::sha256(b"grant-bound QSR report"))?;
    let limits = QsrQueryLimits::default();
    let now = || TimestampNs(0);
    for missing in [
        "ADP-REPLAY-001",
        RuntimeGrant::AgentQuery.as_str(),
        RuntimeGrant::ReadMedia.as_str(),
    ] {
        let mut spec = authority_spec(&request, limits)?;
        spec.capabilities.retain(|grant| grant != missing);
        let authority = ContextAuthority::new_root(spec)?;
        assert!(matches!(
            QsrSourceReadPermit::authorize(&authority, &root, &request, limits, &now),
            Err(QsrQueryError::Unauthorized)
        ));
    }
    for change in 0..4 {
        let mut spec = authority_spec(&request, limits)?;
        match change {
            0 => spec.principal = "principal:wrong-operator".into(),
            1 => spec.anchor_universe = ContentDigest::sha256(b"wrong report universe"),
            2 => spec.generation = 2,
            _ => spec.budgets = fss_core::BudgetVector::ZERO,
        }
        let authority = ContextAuthority::new_root(spec)?;
        assert!(matches!(
            QsrSourceReadPermit::authorize(&authority, &root, &request, limits, &now),
            Err(QsrQueryError::Unauthorized)
        ));
    }
    assert!(!root.exists());
    Ok(())
}

#[test]
fn cancellation_and_expiry_are_live_before_source_open() -> Test {
    let directory = Directory::new("agent-qsr-live-admission")?;
    let root = directory.0.join("absent");
    let request = request(ContentDigest::sha256(b"time-bound QSR report"))?;
    let limits = QsrQueryLimits::default();
    let mut spec = authority_spec(&request, limits)?;
    spec.deadline = Some(TimestampNs(10));
    let authority = ContextAuthority::new_root(spec)?;
    let clock = AtomicI64::new(0);
    let now = || TimestampNs(i128::from(clock.load(Ordering::SeqCst)));
    let permit = QsrSourceReadPermit::authorize(&authority, &root, &request, limits, &now)?;
    assert!(matches!(
        query_qsr_in_deployment(&root, &request, limits, Some(&permit), &|| true),
        Err(QsrQueryError::Cancelled)
    ));
    clock.store(10, Ordering::SeqCst);
    assert!(matches!(
        query_qsr_in_deployment(&root, &request, limits, Some(&permit), &|| false),
        Err(QsrQueryError::Unauthorized)
    ));
    assert!(!root.exists());
    Ok(())
}

#[test]
fn bounded_or_corrupt_source_reads_never_deliver_an_empty_success() -> Test {
    let fixture = Fixture::new("agent-qsr-source-refusals")?;
    let before = fixture.source.journals()?;
    let request = request(fixture.report)?;
    let now = || TimestampNs(0);
    let mut limits = QsrQueryLimits::default();
    limits.read.max_read_bytes = 1;
    let authority = ContextAuthority::new_root(authority_spec(&request, limits)?)?;
    let permit =
        QsrSourceReadPermit::authorize(&authority, &fixture.source.root, &request, limits, &now)?;
    assert!(matches!(
        query_qsr_in_deployment(
            &fixture.source.root,
            &request,
            limits,
            Some(&permit),
            &|| false
        ),
        Err(QsrQueryError::Source(_))
    ));
    drop(permit);
    let mut corrupt = fs::read(&fixture.source.chunk)?;
    *corrupt.last_mut().ok_or("original bytes")? ^= 1;
    fs::write(&fixture.source.chunk, &corrupt)?;
    let limits = QsrQueryLimits::default();
    let authority = ContextAuthority::new_root(authority_spec(&request, limits)?)?;
    let permit =
        QsrSourceReadPermit::authorize(&authority, &fixture.source.root, &request, limits, &now)?;
    assert!(
        query_qsr_in_deployment(
            &fixture.source.root,
            &request,
            limits,
            Some(&permit),
            &|| false
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.source.chunk)?, corrupt);
    assert_eq!(fixture.source.journals()?, before);
    Ok(())
}

#[test]
fn exact_current_anchor_pin_refuses_after_effect_history_advances() -> Test {
    let fixture = Fixture::new("agent-qsr-anchor-pin")?;
    let mut request = request(fixture.report)?;
    let limits = QsrQueryLimits::default();
    let authority = ContextAuthority::new_root(authority_spec(&request, limits)?)?;
    let now = || TimestampNs(0);
    let permit =
        QsrSourceReadPermit::authorize(&authority, &fixture.source.root, &request, limits, &now)?;
    let result = query_qsr_in_deployment(
        &fixture.source.root,
        &request,
        limits,
        Some(&permit),
        &|| false,
    )?;
    request.expected_anchor =
        Some(AnchorToken::parse(&result.anchor_token).ok_or("current anchor")?);
    drop(permit);
    let permit =
        QsrSourceReadPermit::authorize(&authority, &fixture.source.root, &request, limits, &now)?;
    let cx = context(&fixture.source.root)?;
    // This explicit writer reconciliation advances the committed effect prefix in the fixture.
    drop(ReferenceDeployment::open(&fixture.source.root, SITE, &cx)?);
    cx.drain_and_finalize();
    let before = fixture.source.journals()?;
    assert!(matches!(
        query_qsr_in_deployment(
            &fixture.source.root,
            &request,
            limits,
            Some(&permit),
            &|| false
        ),
        Err(QsrQueryError::AnchorChanged)
    ));
    assert_eq!(fixture.source.journals()?, before);
    Ok(())
}
