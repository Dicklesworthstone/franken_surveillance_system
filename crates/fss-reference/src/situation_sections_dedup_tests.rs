//! Pins the withheld-statement guard in the `knowledge` and `not_applicable` context lanes.
//!
//! A statement-withholding cell (one carrying a redaction basis) is refused by
//! `KnowledgeCell::validate` on the `known`, `estimated`, and `not_applicable` states, and every
//! public entry point (`ReferenceSituation::verify`, `required_context_item_ids`,
//! `project_reference_situation`, `ReferenceSituationPublication::verify`) validates the capsule
//! before `context_candidates` runs. Those two lanes therefore cannot see a withholding cell
//! through the public API. The guard is still pinned here, by calling `context_candidates` and
//! `same_disclosed_statement` directly on unvalidated cells, so dropping it from either lane or
//! from the helper fails a test.

use std::error::Error;

use fss_core::{KnowledgeCell, KnowledgeState};

use super::{RedundancyRecord, context_candidates, same_disclosed_statement};
use crate::situation_sections_tests::{situation_with_cells, withheld_cell};

/// A cell in `state` that withholds `secret`; `KnowledgeCell::validate` refuses it.
fn withholding_cell_on(
    state: KnowledgeState,
    claim_id: &str,
    secret: &str,
) -> Result<KnowledgeCell, Box<dyn Error>> {
    let mut cell = withheld_cell(claim_id, secret, Vec::new())?;
    cell.knowledge_state = state;
    assert!(cell.withholds_statement());
    assert!(
        cell.validate().is_err(),
        "{state:?} must refuse a redaction basis, so no public entry point reaches this lane"
    );
    Ok(cell)
}

/// Sorted candidate item ids and redundancy records for two withholding cells in `state`.
fn lane_candidates(
    state: KnowledgeState,
    first_secret: &str,
    second_secret: &str,
) -> Result<(Vec<String>, Vec<RedundancyRecord>), Box<dyn Error>> {
    let mut situation = situation_with_cells(false, Vec::new())?;
    situation.capsule.frame.knowledge_cells.extend([
        withholding_cell_on(state, "claim:withheld:1", first_secret)?,
        withholding_cell_on(state, "claim:withheld:2", second_secret)?,
    ]);
    let (candidates, redundancy) = context_candidates(&situation)?;
    for candidate in &candidates {
        for secret in [first_secret, second_secret] {
            assert!(
                !candidate.item.content.contains(secret),
                "a context candidate disclosed a withheld statement"
            );
        }
    }
    let mut ids: Vec<String> = candidates
        .into_iter()
        .map(|candidate| candidate.item.item_id)
        .collect();
    ids.sort();
    Ok((ids, redundancy))
}

#[test]
fn knowledge_and_not_applicable_lanes_never_deduplicate_on_withheld_statements()
-> Result<(), Box<dyn Error>> {
    for (state, lane) in [
        (KnowledgeState::Known, "knowledge"),
        (KnowledgeState::Estimated, "knowledge"),
        (KnowledgeState::NotApplicable, "not_applicable"),
    ] {
        let same = lane_candidates(state, "SECRET-same-resident", "SECRET-same-resident")?;
        let different = lane_candidates(state, "SECRET-alice-is-home", "SECRET-bob-is-away")?;
        assert_eq!(
            same, different,
            "{state:?}: equality of withheld statements changed the {lane} lane"
        );
        for claim in ["claim:withheld:1", "claim:withheld:2"] {
            let item_id = format!("context:{lane}:{claim}");
            assert!(
                same.0.contains(&item_id),
                "{state:?}: {item_id} was deduplicated away"
            );
        }
        assert!(
            same.1.iter().all(|record| record.kind != lane),
            "{state:?}: the {lane} lane recorded a withheld-statement duplicate"
        );
    }
    Ok(())
}

#[test]
fn same_disclosed_statement_never_compares_withheld_statements() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-same-resident";
    let mut disclosed = withheld_cell("claim:disclosed:1", secret, Vec::new())?;
    disclosed.knowledge_state = KnowledgeState::Known;
    disclosed.state_basis = None;
    assert!(!disclosed.withholds_statement());
    let mut disclosed_twin = disclosed.clone();
    disclosed_twin.claim_id = "claim:disclosed:2".to_owned();
    assert!(
        same_disclosed_statement(&disclosed, &disclosed_twin),
        "equal disclosed statements are duplicates"
    );

    for state in [
        KnowledgeState::Known,
        KnowledgeState::Estimated,
        KnowledgeState::NotApplicable,
        KnowledgeState::Redacted,
    ] {
        let mut withheld = withheld_cell("claim:withheld:1", secret, Vec::new())?;
        withheld.knowledge_state = state;
        assert!(withheld.withholds_statement());
        let mut withheld_twin = withheld.clone();
        withheld_twin.claim_id = "claim:withheld:2".to_owned();
        assert!(
            !same_disclosed_statement(&withheld, &withheld_twin),
            "{state:?}: two withheld statements were compared"
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
