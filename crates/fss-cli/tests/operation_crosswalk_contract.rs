#![forbid(unsafe_code)]
//! Contract test suite for MCP/CLI/library operation registry crosswalk (fss-x4a.25.1 / FSS-176).
//!
//! Verifies:
//! 1. All 14 registered fss/1 operations are present in the crosswalk.
//! 2. Total bijective mapping between operation IDs, CLI commands, library entry points, and MCP tool names.
//! 3. Zero name collisions across any presentation or interface surface.
//! 4. Every mapping carries stable error identities and exit identities.
//! 5. Validation fails closed on collisions, missing surfaces, unregistered error codes, and empty registries.

use std::collections::HashSet;
use std::error::Error;

use fss_cli::crosswalk::{
    CrosswalkValidationError, REGISTERED_OPERATION_CROSSWALK, lookup_by_cli_command,
    lookup_by_library_entry_point, lookup_by_mcp_tool_name, lookup_by_operation_id,
    lookup_by_operation_name, validate_crosswalk_entries,
};
use fss_cli::error::ExitIdentity;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn test_all_14_operations_registered_in_crosswalk() -> TestResult {
    assert_eq!(
        REGISTERED_OPERATION_CROSSWALK.len(),
        14,
        "Exactly 14 operations must be registered in the crosswalk"
    );

    let expected_ids = [
        "AOP-001", "AOP-002", "AOP-003", "AOP-004", "AOP-005", "AOP-006", "AOP-007", "AOP-008",
        "AOP-009", "AOP-010", "AOP-011", "AOP-012", "AOP-013", "AOP-014",
    ];

    let actual_ids: Vec<&str> = REGISTERED_OPERATION_CROSSWALK
        .iter()
        .map(|e| e.operation_id)
        .collect();

    assert_eq!(actual_ids, expected_ids);
    Ok(())
}

#[test]
fn test_bijective_surface_lookups() -> TestResult {
    for entry in REGISTERED_OPERATION_CROSSWALK {
        let by_id = lookup_by_operation_id(entry.operation_id);
        assert_eq!(by_id, Some(entry));

        let by_name = lookup_by_operation_name(entry.operation_name);
        assert_eq!(by_name, Some(entry));

        let by_cli = lookup_by_cli_command(entry.cli_command);
        assert_eq!(by_cli, Some(entry));

        let by_mcp = lookup_by_mcp_tool_name(entry.mcp_tool_name);
        assert_eq!(by_mcp, Some(entry));

        let by_lib = lookup_by_library_entry_point(entry.library_entry_point);
        assert_eq!(by_lib, Some(entry));
    }

    assert_eq!(lookup_by_operation_id("AOP-999"), None);
    assert_eq!(lookup_by_cli_command("fss non_existent"), None);
    assert_eq!(lookup_by_mcp_tool_name("unknown_tool"), None);
    assert_eq!(lookup_by_library_entry_point("fss_fake::unknown"), None);

    Ok(())
}

#[test]
fn test_no_surface_name_collisions() -> TestResult {
    let mut cli_cmds = HashSet::new();
    let mut mcp_tools = HashSet::new();
    let mut lib_entries = HashSet::new();
    let mut op_names = HashSet::new();

    for entry in REGISTERED_OPERATION_CROSSWALK {
        assert!(
            cli_cmds.insert(entry.cli_command),
            "Duplicate CLI command: {}",
            entry.cli_command
        );
        assert!(
            mcp_tools.insert(entry.mcp_tool_name),
            "Duplicate MCP tool name: {}",
            entry.mcp_tool_name
        );
        assert!(
            lib_entries.insert(entry.library_entry_point),
            "Duplicate library entry point: {}",
            entry.library_entry_point
        );
        assert!(
            op_names.insert(entry.operation_name),
            "Duplicate operation name: {}",
            entry.operation_name
        );
    }

    Ok(())
}

#[test]
fn test_all_entries_carry_valid_errors_and_exit_identities() -> TestResult {
    for entry in REGISTERED_OPERATION_CROSSWALK {
        assert!(
            entry.primary_error_id.starts_with("ERR-"),
            "Primary error id must start with ERR-: {}",
            entry.primary_error_id
        );
        assert!(
            !entry.error_identities.is_empty(),
            "Error identities must not be empty for {}",
            entry.operation_id
        );
        for err_id in entry.error_identities {
            assert!(
                err_id.starts_with("ERR-"),
                "Error id must start with ERR-: {}",
                err_id
            );
        }

        assert!(
            !entry.exit_identities.is_empty(),
            "Exit identities must not be empty for {}",
            entry.operation_id
        );
        for exit in entry.exit_identities {
            assert!(
                exit.identifier.starts_with("EXIT-"),
                "Exit identifier must start with EXIT-: {}",
                exit.identifier
            );
        }
    }

    Ok(())
}

#[test]
fn test_live_crosswalk_passes_validation() -> TestResult {
    let allowed_errors = [
        "ERR-AUTH-DENIED-001",
        "ERR-AGENT-SESSION-STALE-001",
        "ERR-BUDGET-EXHAUSTED-001",
        "ERR-OP-EXECUTION-FAILED-001",
        "ERR-AGENT-HANDOFF-INVALID-001",
        "ERR-AGENT-RESUME-INDETERMINATE-001",
        "ERR-AGENT-CONTEXT-INCOMPLETE-001",
        "ERR-AGENT-RESNAPSHOT-001",
        "ERR-STREAM-CONTINUITY-001",
        "ERR-AGENT-AMBIGUOUS-001",
        "ERR-AGENT-CASE-BUDGET-001",
        "ERR-PRECONDITION-STALE-001",
        "ERR-AGENT-NO-AFFORDANCE-001",
        "ERR-AGENT-AFFORDANCE-INVALIDATED-001",
        "ERR-EFFECT-INDETERMINATE-001",
        "ERR-IDEMPOTENCY-CONFLICT-001",
        "ERR-LEASE-STALE-001",
        "ERR-OP-TIMEOUT-001",
        "ERR-QUIESCENCE-001",
        "ERR-REPLAY-DIVERGED-001",
        "ERR-EVIDENCE-MISSING-001",
        "ERR-AGENT-LEARNING-UNSUPPORTED-001",
        "ERR-CLI-RUNTIME-FAILURE-001",
        "ERR-CLOCK-UNCERTAIN-001",
    ];

    validate_crosswalk_entries(REGISTERED_OPERATION_CROSSWALK, &allowed_errors)?;
    Ok(())
}

#[test]
fn test_validator_fails_closed_on_empty_registry() -> TestResult {
    let res = validate_crosswalk_entries(&[], &[]);
    assert_eq!(res, Err(CrosswalkValidationError::EmptyRegistry));
    Ok(())
}

#[test]
fn test_validator_fails_closed_on_cli_collision() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[1].cli_command = entries[0].cli_command;

    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::CliCommandCollision { .. })
    ));
    Ok(())
}

#[test]
fn test_validator_fails_closed_on_mcp_collision() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[1].mcp_tool_name = entries[0].mcp_tool_name;

    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::McpToolCollision { .. })
    ));
    Ok(())
}

#[test]
fn test_validator_fails_closed_on_library_collision() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[1].library_entry_point = entries[0].library_entry_point;

    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::LibraryEntryCollision { .. })
    ));
    Ok(())
}

#[test]
fn test_validator_fails_closed_on_missing_surface() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[0].cli_command = "";

    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::MissingSurfaceMapping {
            surface: "cli_command",
            ..
        })
    ));
    Ok(())
}

#[test]
fn test_validator_fails_closed_on_unregistered_error() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[0].error_identities = &["ERR-UNREGISTERED-FICTIONAL-001"];

    let res = validate_crosswalk_entries(&entries, &["ERR-AUTH-DENIED-001"]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::UnregisteredError { .. })
    ));
    Ok(())
}

#[test]
fn test_unregistered_exit_identity_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    static FAKE_EXIT: [ExitIdentity; 1] = [ExitIdentity {
        code: 99,
        identifier: "EXIT-NONEXISTENT-FICTIONAL-999",
    }];
    entries[0].exit_identities = &FAKE_EXIT;
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::InvalidExitIdentity { .. })
    ));
    Ok(())
}

#[test]
fn test_empty_exit_identities_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[0].exit_identities = &[];
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(res.is_err(), "Empty exit identities must fail closed");
    Ok(())
}

#[test]
fn test_duplicate_operation_id_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    let mut dup = entries[0];
    dup.cli_command = "fss custom command";
    dup.mcp_tool_name = "custom_tool";
    dup.library_entry_point = "fss_custom::tool";
    entries.push(dup);
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(
        res.is_err(),
        "Duplicate operation_id AOP-001 must be rejected"
    );
    Ok(())
}

#[test]
fn test_case_and_separator_collision_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[1].mcp_tool_name = "session-open";
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::McpToolCollision { .. })
    ));
    Ok(())
}

#[test]
fn test_empty_primary_error_id_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[0].primary_error_id = "";
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(res.is_err(), "Empty primary_error_id must fail closed");
    Ok(())
}

#[test]
fn test_whitespace_surface_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[0].cli_command = "   ";
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::MissingSurfaceMapping {
            surface: "cli_command",
            ..
        })
    ));
    Ok(())
}

#[test]
fn test_stale_tombstone_entry_fails_closed() -> TestResult {
    let mut entries = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries[0].status = "tombstone";
    let res = validate_crosswalk_entries(&entries, &[]);
    assert!(matches!(
        res,
        Err(CrosswalkValidationError::StaleEntry { .. })
    ));
    Ok(())
}

#[test]
fn test_all_missing_surfaces_fail_closed() -> TestResult {
    let mut entries_mcp = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries_mcp[0].mcp_tool_name = "";
    let res_mcp = validate_crosswalk_entries(&entries_mcp, &[]);
    assert!(matches!(
        res_mcp,
        Err(CrosswalkValidationError::MissingSurfaceMapping {
            surface: "mcp_tool_name",
            ..
        })
    ));

    let mut entries_lib = REGISTERED_OPERATION_CROSSWALK.to_vec();
    entries_lib[0].library_entry_point = "";
    let res_lib = validate_crosswalk_entries(&entries_lib, &[]);
    assert!(matches!(
        res_lib,
        Err(CrosswalkValidationError::MissingSurfaceMapping {
            surface: "library_entry_point",
            ..
        })
    ));
    Ok(())
}

#[test]
fn test_parity_against_json_crosswalk() -> TestResult {
    let json_str = include_str!("../../../architecture/operation_crosswalk.json");
    for entry in REGISTERED_OPERATION_CROSSWALK {
        assert!(json_str.contains(entry.operation_id));
        assert!(json_str.contains(entry.operation_name));
        assert!(json_str.contains(entry.cli_command));
        assert!(json_str.contains(entry.mcp_tool_name));
        assert!(json_str.contains(entry.library_entry_point));
        assert!(json_str.contains(entry.primary_error_id));
        assert!(json_str.contains(entry.status));
    }
    Ok(())
}

#[test]
fn test_compiled_operation_table_equals_frozen_registry() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    assert!(
        frozen_str.contains("\"semanticProtocol\": \"fss/1\""),
        "Frozen registry must specify semanticProtocol fss/1"
    );
    assert!(
        frozen_str.contains("\"schema\": \"fss.public_registry.v1\""),
        "Frozen registry must specify schema fss.public_registry.v1"
    );
    assert!(
        frozen_str.contains("\"freezeDigest\": \"sha256:"),
        "Frozen registry must specify canonical freeze digest"
    );

    // Verify all 14 compiled operations are present with identical coordinates
    for entry in REGISTERED_OPERATION_CROSSWALK {
        assert!(
            frozen_str.contains(entry.operation_id),
            "Frozen registry missing compiled operation_id: {}",
            entry.operation_id
        );
        assert!(
            frozen_str.contains(entry.operation_name),
            "Frozen registry missing compiled operation_name: {}",
            entry.operation_name
        );
        assert!(
            frozen_str.contains(entry.owner),
            "Frozen registry missing compiled owner: {}",
            entry.owner
        );
        assert!(
            frozen_str.contains(entry.status),
            "Frozen registry missing compiled status: {}",
            entry.status
        );
    }

    // Verify all 15 resources are present in the frozen registry
    let expected_resource_ids = [
        "ARES-001", "ARES-002", "ARES-003", "ARES-004", "ARES-005", "ARES-006", "ARES-007",
        "ARES-008", "ARES-009", "ARES-010", "ARES-011", "ARES-012", "ARES-013", "ARES-014",
        "ARES-015",
    ];
    for res_id in expected_resource_ids {
        assert!(
            frozen_str.contains(res_id),
            "Frozen registry missing expected resource_id: {}",
            res_id
        );
    }

    Ok(())
}
