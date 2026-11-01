#![forbid(unsafe_code)]
//! Explicit reconstructed-landmark selections and unchanged retained matching inputs.
//!
//! A selection identifies an already reconstructed hypothesis and its owner-declared
//! enduring-static basis. It cannot supply replacement geometry, descriptors, image
//! pixels, source provenance or error bounds. Parsing does not authenticate a source
//! or establish that the selected physical point will remain static.

use std::collections::BTreeSet;

use fss_cli::json_input::{self, Value};
use fss_cli::json_output::{array, object, string};
use fss_cli::scene_rig::SceneRig;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_twin::PropertyTwin;
use fss_twin::feature_association::{AssociationOptions, FeatureView};
use fss_twin::localization::native::ExtractionOptions;
use fss_twin::reconstruction_atlas::LandmarkSelection;

use super::input::{self, ResolvedFrame, View};
use super::multiview::input as multi;
use super::{Result, fail, input_error};

pub(super) const SCHEMA: &str = "fss.reconstruction_atlas_selection.v1";
pub(super) const MAX_SELECTION_BYTES: usize = 64 * 1024;
const MAX_LANDMARKS: usize = 128;

pub(super) struct Selection {
    pub association_evidence: [u8; 32],
    /// Canonical increasing landmark-ID order, independent of caller row order.
    pub landmarks: Vec<LandmarkSelection>,
    /// Complete normalized declarations, including every enduring-static basis.
    pub declarations: String,
}

/// Strict, bounded selection admission; the native producer resolves hypotheses later.
pub(super) fn parse_selection(bytes: &[u8]) -> Result<Selection> {
    if bytes.len() > MAX_SELECTION_BYTES {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "atlas selection exceeds 65536 bytes",
        ));
    }
    let value = json_input::parse(
        std::str::from_utf8(bytes).map_err(|_| input_error("atlas selection must be UTF-8"))?,
    )
    .map_err(|_| input_error("malformed atlas selection"))?;
    let top = input::fields(&value, &["schema", "association_evidence", "landmarks"])?;
    if input::text(input::get(top, "schema")?)? != SCHEMA {
        return Err(input_error("unsupported exact atlas selection schema"));
    }
    let association_evidence = input::digest(input::get(top, "association_evidence")?)?.bytes();
    let rows = input::get(top, "landmarks")?
        .array()
        .filter(|rows| (1..=MAX_LANDMARKS).contains(&rows.len()))
        .ok_or_else(|| input_error("atlas selection requires one through 128 landmarks"))?;
    let mut landmarks = Vec::new();
    landmarks.try_reserve_exact(rows.len()).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "atlas selection allocation refused",
        )
    })?;
    let mut hypotheses = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut groups = BTreeSet::new();
    for row in rows {
        let row = input::fields(
            row,
            &[
                "hypothesis",
                "landmark",
                "physical_group",
                "feature",
                "enduring_static_basis",
            ],
        )?;
        let landmark = LandmarkSelection {
            hypothesis: input::digest(input::get(row, "hypothesis")?)?.bytes(),
            landmark: input::unsigned(input::get(row, "landmark")?, 1, u64::MAX)?,
            physical_group: input::unsigned(input::get(row, "physical_group")?, 1, u64::MAX)?,
            feature: input::unsigned(input::get(row, "feature")?, 0, u64::from(u32::MAX))? as u32,
            enduring_static_basis: input::digest(input::get(row, "enduring_static_basis")?)?
                .bytes(),
        };
        if !hypotheses.insert(landmark.hypothesis)
            || !ids.insert(landmark.landmark)
            || !groups.insert(landmark.physical_group)
        {
            return Err(input_error(
                "atlas selection repeats a hypothesis, landmark or physical group",
            ));
        }
        landmarks.push(landmark);
    }
    landmarks.sort_by_key(|landmark| landmark.landmark);
    let declarations = selection_json(association_evidence, &landmarks);
    Ok(Selection {
        association_evidence,
        landmarks,
        declarations,
    })
}

/// Resolve all explicit twin-feature ordinals before opening or decoding source media.
pub(super) fn validate_twin(selection: &Selection, twin: &PropertyTwin) -> Result<()> {
    if selection
        .landmarks
        .iter()
        .any(|landmark| twin.features().get(landmark.feature as usize).is_none())
    {
        return Err(input_error(
            "atlas selection references a feature absent from the exact twin",
        ));
    }
    Ok(())
}

fn pin(bytes: [u8; 32]) -> String {
    string(&ContentDigest::new(DigestAlgorithm::Sha256, bytes).to_text())
}

fn selection_json(association_evidence: [u8; 32], landmarks: &[LandmarkSelection]) -> String {
    object(&[
        ("schema", string(SCHEMA)),
        ("association_evidence", pin(association_evidence)),
        (
            "landmarks",
            array(
                &landmarks
                    .iter()
                    .map(|landmark| {
                        object(&[
                            ("hypothesis", pin(landmark.hypothesis)),
                            ("landmark", string(&landmark.landmark.to_string())),
                            (
                                "physical_group",
                                string(&landmark.physical_group.to_string()),
                            ),
                            ("feature", landmark.feature.to_string()),
                            ("enduring_static_basis", pin(landmark.enduring_static_basis)),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}

/// A typed dispatch to the original query parsers and source-binding adapters.
pub(super) enum MatchingQuery {
    Pair(Box<input::Query>),
    Multiview(Box<multi::Query>),
}

pub(super) fn parse_matching(bytes: &[u8], rig_digest: ContentDigest) -> Result<MatchingQuery> {
    let document = json_input::parse(
        std::str::from_utf8(bytes)
            .map_err(|_| input_error("retained atlas matching query must be UTF-8"))?,
    )
    .map_err(|_| input_error("malformed retained atlas matching query"))?;
    let fields = document
        .object()
        .ok_or_else(|| input_error("retained atlas matching query must be an object"))?;
    match input::text(input::get(fields, "schema")?)? {
        input::SCHEMA | input::SCHEMA_V2 => {
            input::parse(bytes, rig_digest).map(|query| MatchingQuery::Pair(Box::new(query)))
        }
        multi::SCHEMA | multi::SCHEMA_V2 => {
            multi::parse(bytes, rig_digest).map(|query| MatchingQuery::Multiview(Box::new(query)))
        }
        _ => Err(input_error(
            "unsupported exact retained atlas matching schema",
        )),
    }
}

impl MatchingQuery {
    pub(super) fn views(&self) -> &[View] {
        match self {
            Self::Pair(query) => &query.views,
            Self::Multiview(query) => &query.views,
        }
    }

    pub(super) fn extraction(&self) -> ExtractionOptions {
        match self {
            Self::Pair(query) => query.extraction,
            Self::Multiview(query) => query.extraction,
        }
    }

    pub(super) fn matching(&self) -> AssociationOptions {
        match self {
            Self::Pair(query) => query.matching,
            Self::Multiview(query) => query.matching,
        }
    }

    pub(super) fn declarations(&self) -> &str {
        match self {
            Self::Pair(query) => &query.declarations,
            Self::Multiview(query) => &query.declarations,
        }
    }

    pub(super) fn bind(
        &self,
        resolved: &[ResolvedFrame<'_>],
        rig: &SceneRig,
    ) -> Result<Vec<FeatureView>> {
        match self {
            Self::Pair(query) => {
                let [left, right] = resolved else {
                    return Err(input_error(
                        "retained pair atlas requires exactly two source snapshots",
                    ));
                };
                input::bind(query, [snapshot(left), snapshot(right)], rig).map(Vec::from)
            }
            Self::Multiview(query) => multi::bind(query, resolved, rig),
        }
    }
}

fn snapshot<'a>(source: &ResolvedFrame<'a>) -> ResolvedFrame<'a> {
    ResolvedFrame {
        capsule: source.capsule,
        import_identity: source.import_identity,
        segment: source.segment,
        dimensions: source.dimensions,
        exposure: source.exposure,
        luma: source.luma,
        frame: source.frame,
        allowed_mask_digest: source.allowed_mask_digest,
        codec: source.codec,
        range_start: source.range_start,
        range_count: source.range_count,
        rectification: source.rectification,
    }
}

#[cfg(test)]
#[path = "atlas_input_tests.rs"]
mod tests;
