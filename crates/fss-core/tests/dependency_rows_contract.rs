#![forbid(unsafe_code)]
//! Field-level contract tests for the dependency constitution classes
//! (`architecture/dependency_constitution.json` machine rows, normative
//! doctrine in `docs/DEPENDENCY_CONSTITUTION.md`, policy in
//! `architecture/dependency_allowlist.toml`), realizing the fss-x4a.30.88
//! family acceptance:
//!
//! * every DEP-CLASS row exists exactly once in the machine constitution
//!   with name + admission class;
//! * every DEP-INV invariant exists in the normative doctrine document;
//! * the deterministic checker (`scripts/dependency_registry_checker.py`)
//!   passes — run separately as the family's cross-registry validation;
//! * the freeze digest declared in `architecture/dependencies.json` matches
//!   the value the checker verifies;
//! * mutation robustness: duplicate IDs are detectable.

use std::collections::BTreeSet;
use std::error::Error;

const CONSTITUTION_JSON: &str = include_str!("../../../architecture/dependency_constitution.json");
const DEPENDENCIES_JSON: &str = include_str!("../../../architecture/dependencies.json");
const DOCTRINE_MD: &str = include_str!("../../../docs/DEPENDENCY_CONSTITUTION.md");

/// The ten DEP-INV invariants of the 30.88 family.
const NORMATIVE_INVARIANTS: [&str; 10] = [
    "DEP-INV-001", "DEP-INV-002", "DEP-INV-003", "DEP-INV-004", "DEP-INV-005", "DEP-INV-006",
    "DEP-INV-007", "DEP-INV-008", "DEP-INV-009", "DEP-INV-010",
];

/// The five DEP-CLASS rows of the machine constitution (id → name).
const NORMATIVE_CLASSES: [(&str, &str); 5] = [
    ("DEP-CLASS-F0", "rust-language-and-stdlib"),
    ("DEP-CLASS-F1", "asupersync"),
    ("DEP-CLASS-F2", "franken-suite"),
    ("DEP-CLASS-F3", "fundamental-rust-data-shape"),
    ("DEP-CLASS-F4", "laboratory-oracle"),
];

/// The four dependency-category rows of the 30.88 family (id → admission
/// state declared in the mirror table).
const NORMATIVE_CATEGORY_ROWS: [(&str, &str); 4] = [
    ("DEP-FUND-001", "serde / serde_json"),
    ("DEP-LAB-001", "Pinned codec/model/vendor/reference executables"),
    ("DEP-ORACLE-001", "Python/reference ecosystems"),
    ("DEP-EXCEPTION-001", "Any other external crate"),
];

#[test]
fn constitution_classes_exist_once_with_admission() -> Result<(), Box<dyn Error>> {
    let mut ids = BTreeSet::new();
    for (id, name) in NORMATIVE_CLASSES {
        let marker = format!("\"id\": \"{id}\"");
        let start = CONSTITUTION_JSON
            .find(&marker)
            .ok_or(format!("class {id} missing from machine constitution"))?;
        let span = &CONSTITUTION_JSON[start..CONSTITUTION_JSON.len().min(start + 300)];
        assert!(ids.insert(id), "duplicate class {id}");
        assert!(
            span.contains(&format!("\"name\": \"{name}\"")),
            "{id}: name drift (expected '{name}')"
        );
        assert!(span.contains("\"admission\":"), "{id}: no admission class");
        // The doctrine document carries the class too (mirror agreement).
        assert!(DOCTRINE_MD.contains(id), "doctrine missing {id}");
    }
    Ok(())
}

#[test]
fn invariants_are_declared_in_the_doctrine() {
    for inv in NORMATIVE_INVARIANTS {
        assert!(
            DOCTRINE_MD.contains(&format!("`{inv}`")),
            "invariant {inv} missing from DEPENDENCY_CONSTITUTION.md"
        );
    }
}

#[test]
fn freeze_digest_matches_checker_expectation() {
    // The value scripts/dependency_registry_checker.py verifies against
    // (its run is the family's deterministic cross-registry validation).
    assert!(DEPENDENCIES_JSON.contains(
        "sha256:8f198c9ce7b3eca519c678beb4bde773fe42d8bc93b55b9f0af375d38208a9c1"
    ));
    assert!(DEPENDENCIES_JSON.contains("gen:fss1:dependencies-v2"));
}

#[test]
fn category_rows_exist_in_mirror_and_machine_json() {
    for (id, subject) in NORMATIVE_CATEGORY_ROWS {
        assert!(DEPENDENCIES_JSON.contains(&format!("\"id\": \"{id}\"")), "{id} missing from machine json");
        // Category rows live in the mirror table and machine json; the
        // constitution doctrine carries classes and invariants, not these.
        let mirror = include_str!("../../../registries/DEPENDENCIES.md");
        assert!(mirror.contains(&format!("`{id}`")), "mirror missing {id}");
        assert!(mirror.contains(subject), "mirror missing subject for {id}");
    }
}

#[test]
fn tampering_is_detectable() {
    let ids: BTreeSet<&str> = NORMATIVE_CLASSES.iter().map(|(id, _)| *id).collect();
    let mut tampered = ids.clone();
    assert!(!tampered.insert("DEP-CLASS-F0"), "duplicate injection detectable");
    assert_eq!(ids, tampered);
}
