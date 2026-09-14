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

/// A cell that withholds `secret`.
fn withholding_cell_on(
    claim_id: &str,
    secret: &str,
) -> Result<KnowledgeCell, Box<dyn Error>> {
    let cell = withheld_cell(claim_id, secret, Vec::new())?;
    assert!(cell.withholds_statement());
    Ok(cell)
}

/// Sorted candidate item ids and redundancy records for two withholding cells.
fn lane_candidates(
    first_secret: &str,
    second_secret: &str,
) -> Result<(Vec<String>, Vec<RedundancyRecord>), Box<dyn Error>> {
    let mut situation = situation_with_cells(false, Vec::new())?;
    situation.capsule.frame.knowledge_cells.extend([
        withholding_cell_on("claim:withheld:1", first_secret)?,
        withholding_cell_on("claim:withheld:2", second_secret)?,
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
fn epistemic_boundary_lane_never_deduplicates_on_withheld_statements()
-> Result<(), Box<dyn Error>> {
    let same = lane_candidates("SECRET-same-resident", "SECRET-same-resident")?;
    let different = lane_candidates("SECRET-alice-is-home", "SECRET-bob-is-away")?;
    assert_eq!(
        same, different,
        "equality of withheld statements changed the epistemic_boundary lane"
    );
    for claim in ["claim:withheld:1", "claim:withheld:2"] {
        let item_id = format!("context:epistemic_boundary:{claim}");
        assert!(
            same.0.contains(&item_id),
            "{item_id} was deduplicated away"
        );
    }
    assert!(
        same.1.iter().all(|record| record.kind != "epistemic_boundary"),
        "the epistemic_boundary lane recorded a withheld-statement duplicate"
    );
    Ok(())
}

#[test]
fn same_disclosed_statement_never_compares_withheld_statements() -> Result<(), Box<dyn Error>> {
    let secret = "SECRET-same-resident";
    let cell = withheld_cell("claim:disclosed:1", secret, Vec::new())?;
    let mut params = cell.to_params();
    params.knowledge_state = KnowledgeState::Known;
    params.state_basis = None;
    let disclosed = KnowledgeCell::new(params)?;
    assert!(!disclosed.withholds_statement());
    let mut twin_params = disclosed.to_params();
    twin_params.claim_id = "claim:disclosed:2".to_owned();
    let disclosed_twin = KnowledgeCell::new(twin_params)?;
    assert!(
        same_disclosed_statement(&disclosed, &disclosed_twin),
        "equal disclosed statements are duplicates"
    );

    let withheld = withheld_cell("claim:withheld:1", secret, Vec::new())?;
    assert!(withheld.withholds_statement());
    let withheld_twin = withheld_cell("claim:withheld:2", secret, Vec::new())?;
    assert!(withheld_twin.withholds_statement());
    assert!(
        !same_disclosed_statement(&withheld, &withheld_twin),
        "two withheld statements were compared"
    );
    assert!(
        !same_disclosed_statement(&withheld, &disclosed),
        "a withheld statement was compared with a disclosed one"
    );
    assert!(
        !same_disclosed_statement(&disclosed, &withheld),
        "a disclosed statement was compared with a withheld one"
    );
    Ok(())
}
