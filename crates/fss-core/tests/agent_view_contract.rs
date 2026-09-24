#![forbid(unsafe_code)]
//! Contract tests for registered `fss/1` agent views (AVIEW-001..008).
//!
//! Pins registry row order and bijectivity, the canonical text row encoding
//! against typed accessors, canonical binary round-trip and tamper refusal,
//! token budget discipline, and the operation default-view binding table.

use fss_core::{
    AgentOperation, AgentView, CanonicalDecode, CanonicalEncode, CanonicalEncoder,
    REGISTERED_VIEW_COUNT,
};

#[test]
fn test_view_row_order_and_bijectivity() {
    let rows = AgentView::ALL_VIEWS.to_vec();
    assert_eq!(rows.len(), REGISTERED_VIEW_COUNT);
    for (index, view) in rows.iter().enumerate() {
        assert_eq!(view.id(), format!("AVIEW-{:03}", index + 1));
    }
    for (i, a) in rows.iter().enumerate() {
        for b in rows.iter().skip(i + 1) {
            assert_ne!(a.id(), b.id());
            assert_ne!(a.name(), b.name());
            assert_ne!(a.canonical_row_encoding(), b.canonical_row_encoding());
            assert_ne!(a.row_digest(), b.row_digest());
        }
    }
    let mut sorted = rows.clone();
    sorted.sort();
    assert_eq!(sorted, rows);
}

#[test]
fn test_view_parsing_accepts_names_only() -> Result<(), Box<dyn std::error::Error>> {
    use std::str::FromStr;
    for view in AgentView::ALL_VIEWS {
        assert_eq!(AgentView::from_id(view.id())?, view);
        assert_eq!(AgentView::from_name(view.name())?, view);
        assert!(AgentView::from_name(view.id()).is_err());
    }
    assert!(AgentView::from_id("AVIEW-000").is_err());
    assert!(AgentView::from_id("AVIEW-009").is_err());
    assert!(AgentView::from_str("pulse").is_ok());
    assert!(AgentView::from_str("AVIEW-001").is_err());
    assert!(AgentView::from_str("").is_err());
    Ok(())
}

#[test]
fn test_view_canonical_row_matches_accessors() -> Result<(), Box<dyn std::error::Error>> {
    for view in AgentView::ALL_VIEWS {
        let fields: Vec<&str> = view.canonical_row_encoding().split('|').collect();
        assert_eq!(fields.len(), 7, "view {} must have 7 fields", view.id());
        assert_eq!(fields[0], view.id());
        assert_eq!(fields[1], view.name());
        assert_eq!(fields[2], view.owner());
        assert_eq!(fields[3], view.target_tokens().to_string());
        assert_eq!(fields[4], view.maximum_tokens().to_string());
        assert_eq!(fields[5], view.gate());
        let sections: Vec<&str> = fields[6].split(';').collect();
        assert_eq!(sections, view.required_sections());
        assert!(!view.purpose().is_empty());
        view.validate_row()?;
    }
    Ok(())
}

#[test]
fn test_view_binary_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    for view in AgentView::ALL_VIEWS {
        let mut encoder = CanonicalEncoder::new();
        view.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        let decoded = AgentView::from_canonical_bytes(&bytes)?;
        assert_eq!(decoded, view, "round trip must preserve {}", view.id());
        let mut cut = bytes.clone();
        cut.pop();
        assert!(AgentView::from_canonical_bytes(&cut).is_err());
    }
    Ok(())
}

#[test]
fn test_view_token_budget_discipline() -> Result<(), Box<dyn std::error::Error>> {
    for view in AgentView::ALL_VIEWS {
        assert!(view.target_tokens() >= 1);
        assert!(view.maximum_tokens() >= view.target_tokens());
        view.validate_row()?;
    }
    // Forensic is the broadest view; pulse is the smallest.
    assert_eq!(AgentView::Forensic.maximum_tokens(), 16_000);
    assert_eq!(AgentView::Pulse.maximum_tokens(), 300);
    Ok(())
}

#[test]
fn test_operation_default_views_bind_registered_views() -> Result<(), Box<dyn std::error::Error>> {
    for operation in AgentOperation::ALL_OPERATIONS {
        let default_id = operation.default_view();
        let view = AgentView::from_id(default_id)?;
        assert!(view.is_default_for(operation));
    }
    // Spot-check the registered pairing table.
    assert!(AgentView::Brief.is_default_for(AgentOperation::SessionOpen));
    assert!(AgentView::Handoff.is_default_for(AgentOperation::SessionResume));
    assert!(AgentView::Pulse.is_default_for(AgentOperation::SessionFollow));
    assert!(AgentView::Operation.is_default_for(AgentOperation::Commit));
    assert!(AgentView::DecisionDiff.is_default_for(AgentOperation::Explain));
    assert!(!AgentView::EpistemicMap.is_default_for(AgentOperation::Wait));
    Ok(())
}

#[test]
fn test_view_digest_stability() {
    for view in AgentView::ALL_VIEWS {
        let digest = view.row_digest();
        assert_eq!(
            AgentView::from_name(view.name()).map(|v| v.row_digest()),
            Ok(digest)
        );
        assert_ne!(view.canonical_digest("fss.other.domain.v1"), digest);
        let encoding = view.canonical_row_encoding();
        assert!(!encoding.contains('\n'));
        assert_eq!(encoding.split('|').count(), 7);
    }
}
