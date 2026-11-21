#![forbid(unsafe_code)]
//! The selected H2 graph is an exact bounded projection with complete retained provenance.

use super::*;
use fss_core::{DecisionArtifactKind, H2DecisionArtifact, RetainedProvenance};
use fss_graph_algorithms::evidence::{FRONTIER_ROOT, object_node, support_node};
use fss_graph_algorithms::weighted::WeightedGraphBuilder;
use fss_reference::agent_event_hydration::build_event_h2_graph_neighborhood;

fn publish(fixture: &Fixture, event: &EventHypothesis) -> Test {
    event.verify()?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
    deployment.publish_event(
        &ReferencePolicyDecision {
            event: event.clone(),
            action: ReferencePolicyAction::Hold,
        },
        &fixture.cx,
    )?;
    Ok(())
}

fn support_event(fixture: &Fixture, id: &str, source: ContentDigest) -> Test<EventHypothesis> {
    let mut event = fixture.event.clone();
    event.event_id = EventId::parse(id)?;
    event.evidence = vec![EventEvidence {
        digest: source,
        class: EvidenceClass::Assertion,
        failure_domain: "sensor:h2-neighborhood".to_owned(),
        supports: true,
        relation: EvidenceEdgeRelation::Supports,
        capsule_digest: None,
        identity_digest: None,
    }];
    event.verify()?;
    Ok(event)
}

fn hydrate(fixture: &Fixture, snapshot: &DeploymentSnapshot) -> Test<H2DecisionArtifact> {
    Ok(build_event_h2_graph_neighborhood(
        snapshot,
        &orientation(snapshot)?,
        &fixture.event.event_id,
        fixture.event.revision_digest(),
        "grant:retained-h2-contract",
        TimestampNs(1000),
    )?)
}

fn neighborhood(artifact: &H2DecisionArtifact) -> Test<&fss_core::GraphNeighborhoodArtifact> {
    match artifact.artifact_kind() {
        DecisionArtifactKind::GraphNeighborhood(value) => Ok(value),
        _ => Err("event H2 returned another artifact kind".into()),
    }
}

#[test]
fn exact_two_hop_incidence_neighborhood_excludes_other_components_and_third_hop() -> Test {
    let fixture = Fixture::new("h2-neighborhood", EventState::Hypothesized, true)?;
    let initial = fixture.snapshot()?;
    let original_catalog = build(&initial, &fixture.event)?;
    let first = hydrate(&fixture, &initial)?;

    // Sharing a raw reference takes four incidence hops between event revisions. Neither
    // that reference nor the global synthetic frontier may collapse the declared radius.
    let unrelated = support_event(
        &fixture,
        "event:unrelated-h2",
        ContentDigest::sha256(SOURCE),
    )?;
    publish(&fixture, &unrelated)?;
    let after_unrelated = fixture.snapshot()?;
    let second = hydrate(&fixture, &after_unrelated)?;
    assert_eq!(neighborhood(&first)?, neighborhood(&second)?);
    assert_eq!(first.payload(), second.payload());
    assert_eq!(first.proof_roots(), second.proof_roots());

    let dependent = support_event(
        &fixture,
        "event:dependent-h2",
        fixture.event.revision_digest(),
    )?;
    publish(&fixture, &dependent)?;
    let before_third_hop = fixture.snapshot()?;
    let third = hydrate(&fixture, &before_third_hop)?;
    let distant = support_event(&fixture, "event:distant-h2", dependent.revision_digest())?;
    publish(&fixture, &distant)?;
    let complete = fixture.snapshot()?;
    let fourth = hydrate(&fixture, &complete)?;
    assert_eq!(neighborhood(&third)?, neighborhood(&fourth)?);
    assert_eq!(third.payload(), fourth.payload());
    assert_eq!(third.proof_roots(), fourth.proof_roots());

    // Independent exact fixture: two supports, each represented by two directed arcs.
    let center = object_node(fixture.event.revision_digest());
    let source = object_node(ContentDigest::sha256(SOURCE));
    let center_support = support_node(fixture.event.revision_digest(), 0);
    let target = object_node(dependent.revision_digest());
    let dependent_support = support_node(dependent.revision_digest(), 0);
    let mut expected = WeightedGraphBuilder::directed("active-support-incidence:v1");
    for id in [
        &center,
        &source,
        &center_support,
        &target,
        &dependent_support,
    ] {
        expected.add_node(id.as_str());
    }
    expected
        .add_arc(&source, &center_support, 1)
        .add_arc(&center_support, &center, 1)
        .add_arc(&center, &dependent_support, 1)
        .add_arc(&dependent_support, &target, 1);
    let expected = expected.build()?;
    let selected = neighborhood(&fourth)?;
    assert_eq!(selected.center_entity_id(), fixture.event.event_id.as_str());
    assert_eq!(selected.radius_hops(), 2);
    assert_eq!(selected.node_count(), 5);
    assert_eq!(selected.edge_count(), 4);
    assert_eq!(selected.subgraph_digest(), expected.digest());
    assert!(expected.index_of(FRONTIER_ROOT).is_none());
    assert!(
        !fourth
            .payload()
            .windows(SOURCE.len())
            .any(|window| window == SOURCE),
        "H2 must not contain source bytes"
    );

    let selected_root = complete
        .event(&fixture.event.event_id)
        .ok_or("selected event missing")?
        .event_root;
    let dependent_root = complete
        .event(&dependent.event_id)
        .ok_or("dependent event missing")?
        .event_root;
    let provenance = RetainedProvenance::new([selected_root, dependent_root])?;
    let expected_proofs = BTreeSet::from([
        selected_root,
        dependent_root,
        fourth.subject_digest(),
        fourth.payload_digest(),
    ]);
    assert_eq!(fourth.proof_roots(), &expected_proofs);
    let bytes = fourth.to_canonical_bytes()?;
    assert_eq!(
        H2DecisionArtifact::decode_verified(&bytes, &provenance)?,
        fourth
    );
    let incomplete = RetainedProvenance::new([selected_root])?;
    assert!(H2DecisionArtifact::decode_verified(&bytes, &incomplete).is_err());

    // H2 compilation is additive: the same snapshot still produces byte-identical H0/H1.
    let rebuilt = build(&initial, &fixture.event)?;
    assert_eq!(original_catalog.descriptor, rebuilt.descriptor);
    assert_eq!(original_catalog.identity, rebuilt.identity);
    assert_eq!(original_catalog.synopsis, rebuilt.synopsis);
    assert_eq!(
        original_catalog.descriptor.handle_id,
        build(&complete, &fixture.event)?.descriptor.handle_id
    );
    Ok(())
}

#[test]
fn historical_support_is_not_rebound_to_a_current_successor() -> Test {
    let fixture = Fixture::new("h2-historical", EventState::Hypothesized, true)?;
    let older = support_event(
        &fixture,
        "event:historical-h2",
        ContentDigest::sha256(SOURCE),
    )?;
    publish(&fixture, &older)?;

    // The selected event now supports the exact old revision. Updating the referenced event
    // cannot grant custody for that reference through its successor's current publication.
    let mut selected = fixture.event.clone();
    selected.revision = 2;
    selected.supersedes = Some(fixture.event.revision_digest());
    selected.evidence[0].digest = older.revision_digest();
    publish(&fixture, &selected)?;
    let mut successor = older.clone();
    successor.revision = 2;
    successor.supersedes = Some(older.revision_digest());
    publish(&fixture, &successor)?;
    let snapshot = fixture.snapshot()?;
    let artifact = build_event_h2_graph_neighborhood(
        &snapshot,
        &orientation(&snapshot)?,
        &selected.event_id,
        selected.revision_digest(),
        "grant:retained-h2-contract",
        TimestampNs(1000),
    )?;
    let center = object_node(selected.revision_digest());
    let reference = object_node(older.revision_digest());
    let support = support_node(selected.revision_digest(), 0);
    let mut expected = WeightedGraphBuilder::directed("active-support-incidence:v1");
    expected
        .add_node(&center)
        .add_node(&reference)
        .add_node(&support)
        .add_arc(&reference, &support, 1)
        .add_arc(&support, &center, 1);
    assert_eq!(
        neighborhood(&artifact)?.subgraph_digest(),
        expected.build()?.digest()
    );
    let successor_root = snapshot
        .event(&successor.event_id)
        .ok_or("successor missing")?
        .event_root;
    assert!(!artifact.proof_roots().contains(&successor_root));
    Ok(())
}

#[test]
fn inconsistent_contributing_revision_refuses_without_a_partial_artifact() -> Test {
    let fixture = Fixture::new("h2-mismatched-custody", EventState::Hypothesized, true)?;
    let dependent = support_event(
        &fixture,
        "event:dependent-h2",
        fixture.event.revision_digest(),
    )?;
    publish(&fixture, &dependent)?;
    let mut snapshot = fixture.snapshot()?;
    let orient = orientation(&snapshot)?;
    let retained = snapshot
        .events
        .iter_mut()
        .find(|retained| retained.event.event_id == dependent.event_id)
        .ok_or("dependent missing")?;
    retained.revision_digest = ContentDigest::sha256(b"wrong witnessed revision");
    assert!(matches!(
        build_event_h2_graph_neighborhood(
            &snapshot,
            &orient,
            &fixture.event.event_id,
            fixture.event.revision_digest(),
            "grant:retained-h2-contract",
            TimestampNs(1000),
        ),
        Err(EventHydrationBuildError::RevisionChanged)
    ));
    Ok(())
}

#[test]
fn no_declared_support_stays_one_node_and_cannot_gain_neighbors_from_counterevidence() -> Test {
    let fixture = Fixture::new("h2-no-support", EventState::Hypothesized, false)?;
    let mut contradiction = support_event(
        &fixture,
        "event:counterevidence-h2",
        fixture.event.revision_digest(),
    )?;
    contradiction.evidence[0].supports = false;
    contradiction.evidence[0].relation = EvidenceEdgeRelation::Contradicts;
    publish(&fixture, &contradiction)?;
    let snapshot = fixture.snapshot()?;
    let artifact = hydrate(&fixture, &snapshot)?;
    let selected = neighborhood(&artifact)?;
    assert_eq!(selected.node_count(), 1);
    assert_eq!(selected.edge_count(), 0);
    let mut expected = WeightedGraphBuilder::directed("active-support-incidence:v1");
    expected.add_node(object_node(fixture.event.revision_digest()));
    assert_eq!(selected.subgraph_digest(), expected.build()?.digest());
    let unrelated_root = snapshot
        .event(&contradiction.event_id)
        .ok_or("counterevidence event missing")?
        .event_root;
    assert!(!artifact.proof_roots().contains(&unrelated_root));
    Ok(())
}
