//! Pins the withheld-statement guard in the `knowledge`, `not_applicable`, and
//! `epistemic_boundary` context lanes.
//!
//! A statement-withholding cell (one carrying a redaction basis) is valid only in the `redacted`
//! state: `KnowledgeCell::new` refuses a redaction basis on `known`, `estimated`, and
//! `not_applicable`, and no public path builds a cell any other way (fss-nozug). The `knowledge`
//! and `not_applicable` lanes therefore never see a withholding cell. The guard is still pinned
//! for every lane with valid cells: a withheld cell and a disclosed lane cell carrying the same
//! statement are never deduplicated against each other, disclosed duplicates are receipted, and
//! `same_disclosed_statement` never compares a withheld statement.

use std::error::Error;

use fss_core::{
    ContentDigest, KnowledgeCell, KnowledgeCellParams, KnowledgeState, ProvenanceClass,
};

use super::{RedundancyRecord, context_candidates, same_disclosed_statement};
use crate::situation_sections_tests::{situation_with_cells, withheld_cell};

/// The lanes that carry disclosed propositions, by knowledge state.
const DISCLOSED_LANES: [(KnowledgeState, &str); 3] = [
    (KnowledgeState::Known, "knowledge"),
    (KnowledgeState::Estimated, "knowledge"),
    (KnowledgeState::NotApplicable, "not_applicable"),
];

/// A cell that withholds `secret`.
fn withholding_cell_on(claim_id: &str, secret: &str) -> Result<KnowledgeCell, Box<dyn Error>> {
    let cell = withheld_cell(claim_id, secret, Vec::new())?;
    assert!(cell.withholds_statement());
    Ok(cell)
}

/// A valid disclosed cell in `state` carrying `statement`.
fn disclosed_cell_on(
    state: KnowledgeState,
    claim_id: &str,
    statement: &str,
) -> Result<KnowledgeCell, Box<dyn Error>> {
    let cell = KnowledgeCell::new(KnowledgeCellParams {
        claim_id: claim_id.to_owned(),
        statement: statement.to_owned(),
        knowledge_state: state,
        provenance: ProvenanceClass::Observed,
        hypothesis: None,
        evidence: vec![ContentDigest::sha256(b"shared-disclosed-evidence")],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?;
    assert!(!cell.withholds_statement());
    Ok(cell)
}

/// A withholding cell in `state` is unrepresentable: the validating constructor refuses the
/// redaction basis, and the refusal discloses nothing it withholds.
fn assert_withholding_unrepresentable_on(state: KnowledgeState) -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-unrepresentable-withheld";
    let mut params = withheld_cell("claim:withheld:probe", secret, Vec::new())?.to_params();
    params.knowledge_state = state;
    let refusal = KnowledgeCell::new(params);
    assert!(
        refusal.is_err(),
        "{state:?} accepted a redaction basis, so a withholding cell could reach its lane"
    );
    assert!(!format!("{refusal:?}").contains(secret));
    Ok(())
}

/// Sorted `(item id, content)` pairs and the redundancy records of one candidate pass.
type Candidates = (Vec<(String, String)>, Vec<RedundancyRecord>);

/// Sorted `(item id, content)` candidates and redundancy records for `cells`.
fn candidates_for(cells: Vec<KnowledgeCell>) -> Result<Candidates, Box<dyn Error>> {
    let mut situation = situation_with_cells(false, Vec::new())?;
    situation.capsule.frame.knowledge_cells.extend(cells);
    let (candidates, redundancy) = context_candidates(&situation)?;
    let mut items: Vec<(String, String)> = candidates
        .into_iter()
        .map(|candidate| (candidate.item.item_id, candidate.item.content))
        .collect();
    items.sort();
    Ok((items, redundancy))
}

/// Sorted candidate item ids and redundancy records for two withholding cells.
fn lane_candidates(
    first_secret: &str,
    second_secret: &str,
) -> Result<(Vec<String>, Vec<RedundancyRecord>), Box<dyn Error>> {
    let (items, redundancy) = candidates_for(vec![
        withholding_cell_on("claim:withheld:1", first_secret)?,
        withholding_cell_on("claim:withheld:2", second_secret)?,
    ])?;
    for (_, content) in &items {
        for secret in [first_secret, second_secret] {
            assert!(
                !content.contains(secret),
                "a context candidate disclosed a withheld statement"
            );
        }
    }
    Ok((items.into_iter().map(|(id, _)| id).collect(), redundancy))
}

#[test]
fn epistemic_boundary_lane_never_deduplicates_on_withheld_statements() -> Result<(), Box<dyn Error>>
{
    let same = lane_candidates("SECRET-same-resident", "SECRET-same-resident")?;
    let different = lane_candidates("SECRET-alice-is-home", "SECRET-bob-is-away")?;
    assert_eq!(
        same, different,
        "equality of withheld statements changed the epistemic_boundary lane"
    );
    for claim in ["claim:withheld:1", "claim:withheld:2"] {
        let item_id = format!("context:epistemic:{claim}");
        assert!(same.0.contains(&item_id), "{item_id} was deduplicated away");
    }
    assert!(
        same.1
            .iter()
            .all(|record| record.kind != "epistemic_boundary"),
        "the epistemic_boundary lane recorded a withheld-statement duplicate"
    );
    Ok(())
}

/// Restores the `known`, `estimated`, and `not_applicable` lanes with valid cells: a withholding
/// cell cannot enter them, a withheld cell and a disclosed lane cell with the same statement are
/// never deduplicated against each other, and disclosed duplicates are receipted in the lane.
#[test]
fn knowledge_and_not_applicable_lanes_never_deduplicate_on_withheld_statements()
-> Result<(), Box<dyn Error>> {
    let secret = "SECRET-same-resident";
    for (state, lane) in DISCLOSED_LANES {
        assert_withholding_unrepresentable_on(state)?;

        let (items, redundancy) = candidates_for(vec![
            withholding_cell_on("claim:withheld:1", secret)?,
            disclosed_cell_on(state, "claim:disclosed:1", secret)?,
        ])?;
        let lane_item = format!("context:{lane}:claim:disclosed:1");
        assert!(
            items.iter().any(|(id, _)| *id == lane_item),
            "{state:?}: {lane_item} was deduplicated away"
        );
        assert!(
            items
                .iter()
                .any(|(id, _)| id == "context:epistemic:claim:withheld:1"),
            "{state:?}: the withheld cell was deduplicated away"
        );
        for (id, content) in &items {
            if id.ends_with("claim:withheld:1") {
                assert!(
                    !content.contains(secret),
                    "{state:?}: {id} disclosed a withheld statement"
                );
            }
        }
        assert!(
            redundancy.iter().all(|record| {
                !record.dropped_item_id.contains("claim:withheld:1")
                    && !record.retained_item_id.contains("claim:withheld:1")
            }),
            "{state:?}: a withheld statement was deduplicated against a disclosed one"
        );

        let statement = "Lane fixture proposition";
        let (_, duplicate_records) = candidates_for(vec![
            disclosed_cell_on(state, "claim:lane:1", statement)?,
            disclosed_cell_on(state, "claim:lane:2", statement)?,
        ])?;
        assert!(
            duplicate_records.iter().any(|record| {
                record.kind == lane
                    && record.dropped_item_id == format!("context:{lane}:claim:lane:2")
                    && record.retained_item_id == format!("context:{lane}:claim:lane:1")
            }),
            "{state:?}: an exact disclosed duplicate in the {lane} lane was not receipted"
        );
        let (distinct_items, distinct_records) = candidates_for(vec![
            disclosed_cell_on(state, "claim:lane:1", "Lane fixture proposition one")?,
            disclosed_cell_on(state, "claim:lane:2", "Lane fixture proposition two")?,
        ])?;
        for claim in ["claim:lane:1", "claim:lane:2"] {
            let item_id = format!("context:{lane}:{claim}");
            assert!(
                distinct_items.iter().any(|(id, _)| *id == item_id),
                "{state:?}: {item_id} was deduplicated away"
            );
        }
        assert!(
            distinct_records.iter().all(|record| record.kind != lane),
            "{state:?}: distinct statements were recorded as duplicates in the {lane} lane"
        );
    }
    Ok(())
}

#[test]
fn same_disclosed_statement_never_compares_withheld_statements() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-same-resident";
    let withheld = withholding_cell_on("claim:withheld:1", secret)?;
    let withheld_twin = withholding_cell_on("claim:withheld:2", secret)?;
    assert!(
        !same_disclosed_statement(&withheld, &withheld_twin),
        "two withheld statements were compared"
    );

    for (state, _) in DISCLOSED_LANES {
        assert_withholding_unrepresentable_on(state)?;
        let disclosed = disclosed_cell_on(state, "claim:disclosed:1", secret)?;
        let disclosed_twin = disclosed_cell_on(state, "claim:disclosed:2", secret)?;
        assert!(
            same_disclosed_statement(&disclosed, &disclosed_twin),
            "{state:?}: equal disclosed statements are duplicates"
        );
        assert!(
            !same_disclosed_statement(&withheld, &disclosed),
            "{state:?}: a withheld statement was compared with a disclosed one"
        );
        assert!(
            !same_disclosed_statement(&disclosed, &withheld),
            "{state:?}: a disclosed statement was compared with a withheld one"
        );
    }
    Ok(())
}
