#![forbid(unsafe_code)]
//! Contract test suite for MCP/CLI/library operation registry crosswalk (fss-x4a.25.1 / FSS-176).
//!
//! Verifies:
//! 1. All 14 registered fss/1 operations are present in the crosswalk.
//! 2. Total bijective mapping between operation IDs, CLI commands, library entry points, and MCP tool names.
//! 3. Zero name collisions across any presentation or interface surface.
//! 4. Every mapping carries stable error identities and exit identities.
//! 5. Validation fails closed on collisions, missing surfaces, unregistered error codes, and empty registries.
//! 6. Planted negative tests adhere to clippy::unwrap_used and clippy::collapsible_if rules.

use std::collections::HashSet;
use std::error::Error;

use fss_cli::crosswalk::{
    CrosswalkValidationError, REGISTERED_OPERATION_CROSSWALK, REGISTERED_RESOURCE_CROSSWALK,
    lookup_by_cli_command, lookup_by_library_entry_point, lookup_by_mcp_tool_name,
    lookup_by_operation_id, lookup_by_operation_name, validate_crosswalk_entries,
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

const EXPECTED_FREEZE_DIGEST: &str =
    "sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8";

#[derive(Debug, Clone, PartialEq)]
enum JsonVal {
    Null,
    Bool(bool),
    Number(i64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(std::collections::BTreeMap<String, JsonVal>),
}

impl JsonVal {
    fn as_str(&self) -> Result<&str, String> {
        match self {
            Self::Str(s) => Ok(s.as_str()),
            _ => Err("expected string".to_string()),
        }
    }
    fn as_obj(&self) -> Result<&std::collections::BTreeMap<String, JsonVal>, String> {
        match self {
            Self::Obj(m) => Ok(m),
            _ => Err("expected object".to_string()),
        }
    }
    fn as_arr(&self) -> Result<&[JsonVal], String> {
        match self {
            Self::Arr(a) => Ok(a.as_slice()),
            _ => Err("expected array".to_string()),
        }
    }
}

fn skip_ws(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

fn parse_json_str(chars: &[char], pos: &mut usize) -> Result<String, String> {
    if *pos >= chars.len() || chars[*pos] != '"' {
        return Err("expected '\"'".to_string());
    }
    *pos += 1;
    let mut s = String::new();
    while *pos < chars.len() {
        match chars[*pos] {
            '"' => {
                *pos += 1;
                return Ok(s);
            }
            '\\' => {
                *pos += 1;
                if *pos >= chars.len() {
                    return Err("unterminated escape".to_string());
                }
                match chars[*pos] {
                    '"' => s.push('"'),
                    '\\' => s.push('\\'),
                    '/' => s.push('/'),
                    'b' => s.push('\x08'),
                    'f' => s.push('\x0c'),
                    'n' => s.push('\n'),
                    'r' => s.push('\r'),
                    't' => s.push('\t'),
                    c => return Err(format!("unknown escape '\\{}'", c)),
                }
                *pos += 1;
            }
            c => {
                s.push(c);
                *pos += 1;
            }
        }
    }
    Err("unterminated string".to_string())
}

fn parse_json_val(chars: &[char], pos: &mut usize) -> Result<JsonVal, String> {
    skip_ws(chars, pos);
    if *pos >= chars.len() {
        return Err("unexpected EOF".to_string());
    }
    match chars[*pos] {
        '{' => {
            *pos += 1;
            let mut map = std::collections::BTreeMap::new();
            skip_ws(chars, pos);
            if *pos < chars.len() && chars[*pos] == '}' {
                *pos += 1;
                return Ok(JsonVal::Obj(map));
            }
            loop {
                skip_ws(chars, pos);
                let key = parse_json_str(chars, pos)?;
                skip_ws(chars, pos);
                if *pos >= chars.len() || chars[*pos] != ':' {
                    return Err("expected ':' in object".to_string());
                }
                *pos += 1;
                let val = parse_json_val(chars, pos)?;
                map.insert(key, val);
                skip_ws(chars, pos);
                if *pos >= chars.len() {
                    return Err("unterminated object".to_string());
                }
                if chars[*pos] == '}' {
                    *pos += 1;
                    return Ok(JsonVal::Obj(map));
                } else if chars[*pos] == ',' {
                    *pos += 1;
                } else {
                    return Err(format!("expected ',' or '}}' at {}", *pos));
                }
            }
        }
        '[' => {
            *pos += 1;
            let mut arr = Vec::new();
            skip_ws(chars, pos);
            if *pos < chars.len() && chars[*pos] == ']' {
                *pos += 1;
                return Ok(JsonVal::Arr(arr));
            }
            loop {
                let val = parse_json_val(chars, pos)?;
                arr.push(val);
                skip_ws(chars, pos);
                if *pos >= chars.len() {
                    return Err("unterminated array".to_string());
                }
                if chars[*pos] == ']' {
                    *pos += 1;
                    return Ok(JsonVal::Arr(arr));
                } else if chars[*pos] == ',' {
                    *pos += 1;
                } else {
                    return Err(format!("expected ',' or ']' at {}", *pos));
                }
            }
        }
        '"' => parse_json_str(chars, pos).map(JsonVal::Str),
        't' => {
            if chars[*pos..].starts_with(&['t', 'r', 'u', 'e']) {
                *pos += 4;
                Ok(JsonVal::Bool(true))
            } else {
                Err("invalid token".to_string())
            }
        }
        'f' => {
            if chars[*pos..].starts_with(&['f', 'a', 'l', 's', 'e']) {
                *pos += 5;
                Ok(JsonVal::Bool(false))
            } else {
                Err("invalid token".to_string())
            }
        }
        'n' => {
            if chars[*pos..].starts_with(&['n', 'u', 'l', 'l']) {
                *pos += 4;
                Ok(JsonVal::Null)
            } else {
                Err("invalid token".to_string())
            }
        }
        '-' | '0'..='9' => {
            let start = *pos;
            if chars[*pos] == '-' {
                *pos += 1;
            }
            while *pos < chars.len() && chars[*pos].is_ascii_digit() {
                *pos += 1;
            }
            let s: String = chars[start..*pos].iter().collect();
            let n: i64 = s.parse().map_err(|e| format!("invalid number {s}: {e}"))?;
            Ok(JsonVal::Number(n))
        }
        c => Err(format!("unexpected character '{c}' at {pos}")),
    }
}

fn parse_json(input: &str) -> Result<JsonVal, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut pos = 0;
    skip_ws(&chars, &mut pos);
    let val = parse_json_val(&chars, &mut pos)?;
    skip_ws(&chars, &mut pos);
    if pos < chars.len() {
        return Err(format!("trailing characters at {pos}"));
    }
    Ok(val)
}

fn validate_frozen_registry_against_compiled(val: &JsonVal) -> Result<(), String> {
    let root = val.as_obj()?;
    let schema = root.get("schema").ok_or("missing schema")?.as_str()?;
    if schema != "fss.public_registry.v1" {
        return Err(format!("unexpected schema: {schema}"));
    }
    let protocol = root
        .get("semanticProtocol")
        .ok_or("missing semanticProtocol")?
        .as_str()?;
    if protocol != "fss/1" {
        return Err(format!("unexpected semanticProtocol: {protocol}"));
    }
    let generation = root
        .get("registryGeneration")
        .ok_or("missing registryGeneration")?
        .as_str()?;
    if generation != "gen:fss1:public-v1" {
        return Err(format!("unexpected registryGeneration: {generation}"));
    }
    let freeze_digest = root
        .get("freezeDigest")
        .ok_or("missing freezeDigest")?
        .as_str()?;
    if freeze_digest != EXPECTED_FREEZE_DIGEST {
        return Err(format!(
            "freeze digest mismatch: expected {EXPECTED_FREEZE_DIGEST}, got {freeze_digest}"
        ));
    }

    // 1. Operations validation
    let ops_arr = root
        .get("operations")
        .ok_or("missing operations")?
        .as_arr()?;
    if ops_arr.len() != REGISTERED_OPERATION_CROSSWALK.len() {
        return Err(format!(
            "operation count mismatch: expected {}, got {}",
            REGISTERED_OPERATION_CROSSWALK.len(),
            ops_arr.len()
        ));
    }

    let mut ops_seen = std::collections::BTreeSet::new();
    for op_val in ops_arr {
        let op_obj = op_val.as_obj()?;
        let op_id = op_obj.get("id").ok_or("missing op id")?.as_str()?;
        if op_id.len() != 7
            || !op_id.starts_with("AOP-")
            || !op_id[4..].chars().all(|c| c.is_ascii_digit())
        {
            return Err(format!("invalid operation id pattern: {op_id}"));
        }
        if !ops_seen.insert(op_id.to_string()) {
            return Err(format!("duplicate operation id: {op_id}"));
        }

        let compiled = REGISTERED_OPERATION_CROSSWALK
            .iter()
            .find(|e| e.operation_id == op_id)
            .ok_or_else(|| format!("unregistered operation id in frozen json: {op_id}"))?;

        let name = op_obj.get("name").ok_or("missing name")?.as_str()?;
        if name != compiled.operation_name {
            return Err(format!(
                "operation {op_id} name mismatch: expected {}, got {}",
                compiled.operation_name, name
            ));
        }
        let owner = op_obj.get("owner").ok_or("missing owner")?.as_str()?;
        if owner != compiled.owner {
            return Err(format!(
                "operation {op_id} owner mismatch: expected {}, got {}",
                compiled.owner, owner
            ));
        }
        let cli_cmd = op_obj
            .get("cliCommand")
            .ok_or("missing cliCommand")?
            .as_str()?;
        if cli_cmd != compiled.cli_command {
            return Err(format!(
                "operation {op_id} cliCommand mismatch: expected {}, got {}",
                compiled.cli_command, cli_cmd
            ));
        }
        let mcp_tool = op_obj
            .get("mcpToolName")
            .ok_or("missing mcpToolName")?
            .as_str()?;
        if mcp_tool != compiled.mcp_tool_name {
            return Err(format!(
                "operation {op_id} mcpToolName mismatch: expected {}, got {}",
                compiled.mcp_tool_name, mcp_tool
            ));
        }
        let status = op_obj.get("status").ok_or("missing status")?.as_str()?;
        if status != compiled.status {
            return Err(format!(
                "operation {op_id} status mismatch: expected {}, got {}",
                compiled.status, status
            ));
        }
    }

    // 2. Resources validation
    let res_arr = root.get("resources").ok_or("missing resources")?.as_arr()?;
    if res_arr.len() != REGISTERED_RESOURCE_CROSSWALK.len() {
        return Err(format!(
            "resource count mismatch: expected {}, got {}",
            REGISTERED_RESOURCE_CROSSWALK.len(),
            res_arr.len()
        ));
    }

    let mut res_seen = std::collections::BTreeSet::new();
    for res_val in res_arr {
        let res_obj = res_val.as_obj()?;
        let res_id = res_obj.get("id").ok_or("missing res id")?.as_str()?;
        if res_id.len() != 8
            || !res_id.starts_with("ARES-")
            || !res_id[5..].chars().all(|c| c.is_ascii_digit())
        {
            return Err(format!("invalid resource id pattern: {res_id}"));
        }
        if !res_seen.insert(res_id.to_string()) {
            return Err(format!("duplicate resource id: {res_id}"));
        }

        let compiled = REGISTERED_RESOURCE_CROSSWALK
            .iter()
            .find(|e| e.resource_id == res_id)
            .ok_or_else(|| format!("unregistered resource id in frozen json: {res_id}"))?;

        let name = res_obj.get("name").ok_or("missing name")?.as_str()?;
        if name != compiled.resource_name {
            return Err(format!(
                "resource {res_id} name mismatch: expected {}, got {}",
                compiled.resource_name, name
            ));
        }
        let uri = res_obj
            .get("uriTemplate")
            .ok_or("missing uriTemplate")?
            .as_str()?;
        if uri != compiled.uri_template {
            return Err(format!(
                "resource {res_id} uriTemplate mismatch: expected {}, got {}",
                compiled.uri_template, uri
            ));
        }
        let owner = res_obj.get("owner").ok_or("missing owner")?.as_str()?;
        if owner != compiled.owner {
            return Err(format!(
                "resource {res_id} owner mismatch: expected {}, got {}",
                compiled.owner, owner
            ));
        }
        let schema = res_obj
            .get("payloadSchema")
            .ok_or("missing payloadSchema")?
            .as_str()?;
        if schema != compiled.payload_schema {
            return Err(format!(
                "resource {res_id} payloadSchema mismatch: expected {}, got {}",
                compiled.payload_schema, schema
            ));
        }
        let comp = res_obj
            .get("compatibilityClass")
            .ok_or("missing compatibilityClass")?
            .as_str()?;
        if comp != compiled.compatibility_class {
            return Err(format!(
                "resource {res_id} compatibilityClass mismatch: expected {}, got {}",
                compiled.compatibility_class, comp
            ));
        }
        let status = res_obj.get("status").ok_or("missing status")?.as_str()?;
        if status != compiled.status {
            return Err(format!(
                "resource {res_id} status mismatch: expected {}, got {}",
                compiled.status, status
            ));
        }
    }

    Ok(())
}

#[test]
fn test_compiled_operation_table_equals_frozen_registry() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    validate_frozen_registry_against_compiled(&json_val).map_err(|e| e.into())
}

fn get_ops_arr_mut(root: &mut JsonVal) -> Option<&mut Vec<JsonVal>> {
    match root {
        JsonVal::Obj(map) => match map.get_mut("operations") {
            Some(JsonVal::Arr(arr)) => Some(arr),
            _ => None,
        },
        _ => None,
    }
}

fn get_op_mut(
    root: &mut JsonVal,
    idx: usize,
) -> Option<&mut std::collections::BTreeMap<String, JsonVal>> {
    match root {
        JsonVal::Obj(map) => match map.get_mut("operations") {
            Some(JsonVal::Arr(arr)) => match arr.get_mut(idx) {
                Some(JsonVal::Obj(op)) => Some(op),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn get_resources_arr_mut(root: &mut JsonVal) -> Option<&mut Vec<JsonVal>> {
    match root {
        JsonVal::Obj(map) => match map.get_mut("resources") {
            Some(JsonVal::Arr(arr)) => Some(arr),
            _ => None,
        },
        _ => None,
    }
}

fn get_resource_mut(
    root: &mut JsonVal,
    idx: usize,
) -> Option<&mut std::collections::BTreeMap<String, JsonVal>> {
    match root {
        JsonVal::Obj(map) => match map.get_mut("resources") {
            Some(JsonVal::Arr(arr)) => match arr.get_mut(idx) {
                Some(JsonVal::Obj(res)) => Some(res),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

#[test]
fn test_planted_negative_swapped_operation_owner_fails() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let mut json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    if let Some(op0) = get_op_mut(&mut json_val, 0) {
        op0.insert(
            "owner".to_string(),
            JsonVal::Str("fss-situation".to_string()),
        );
    }
    let res = validate_frozen_registry_against_compiled(&json_val);
    match res {
        Err(err) => assert!(err.contains("owner mismatch")),
        Ok(()) => return Err("expected validation error but got Ok(())".into()),
    }
    Ok(())
}

#[test]
fn test_planted_negative_extra_operation_fails() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let mut json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    if let Some(ops) = get_ops_arr_mut(&mut json_val) {
        let mut extra = std::collections::BTreeMap::new();
        extra.insert("id".to_string(), JsonVal::Str("AOP-015".to_string()));
        extra.insert("name".to_string(), JsonVal::Str("extra.op".to_string()));
        extra.insert("owner".to_string(), JsonVal::Str("fss-extra".to_string()));
        extra.insert(
            "cliCommand".to_string(),
            JsonVal::Str("fss extra".to_string()),
        );
        extra.insert("mcpToolName".to_string(), JsonVal::Str("extra".to_string()));
        extra.insert("status".to_string(), JsonVal::Str("specified".to_string()));
        ops.push(JsonVal::Obj(extra));
    }
    let res = validate_frozen_registry_against_compiled(&json_val);
    match res {
        Err(err) => assert!(err.contains("operation count mismatch")),
        Ok(()) => return Err("expected validation error but got Ok(())".into()),
    }
    Ok(())
}

#[test]
fn test_planted_negative_non_aop_pattern_operation_fails() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let mut json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    if let Some(op0) = get_op_mut(&mut json_val, 0) {
        op0.insert("id".to_string(), JsonVal::Str("OP-001".to_string()));
    }
    let res = validate_frozen_registry_against_compiled(&json_val);
    match res {
        Err(err) => assert!(err.contains("invalid operation id pattern")),
        Ok(()) => return Err("expected validation error but got Ok(())".into()),
    }
    Ok(())
}

#[test]
fn test_planted_negative_freeze_digest_mismatch_fails() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let mut json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    if let JsonVal::Obj(ref mut root) = json_val {
        root.insert(
            "freezeDigest".to_string(),
            JsonVal::Str(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
        );
    }
    let res = validate_frozen_registry_against_compiled(&json_val);
    match res {
        Err(err) => assert!(err.contains("freeze digest mismatch")),
        Ok(()) => return Err("expected validation error but got Ok(())".into()),
    }
    Ok(())
}

#[test]
fn test_planted_negative_swapped_resource_uri_fails() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let mut json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    if let Some(res0) = get_resource_mut(&mut json_val, 0) {
        res0.insert(
            "uriTemplate".to_string(),
            JsonVal::Str("fss://corrupted".to_string()),
        );
    }
    let res = validate_frozen_registry_against_compiled(&json_val);
    match res {
        Err(err) => assert!(err.contains("uriTemplate mismatch")),
        Ok(()) => return Err("expected validation error but got Ok(())".into()),
    }
    Ok(())
}

#[test]
fn test_planted_negative_extra_resource_fails() -> TestResult {
    let frozen_str = include_str!("../../../architecture/fss1_public_registry.json");
    let mut json_val = parse_json(frozen_str).map_err(|e| format!("parse error: {e}"))?;
    if let Some(res) = get_resources_arr_mut(&mut json_val) {
        let mut extra = std::collections::BTreeMap::new();
        extra.insert("id".to_string(), JsonVal::Str("ARES-016".to_string()));
        extra.insert("name".to_string(), JsonVal::Str("extra.res".to_string()));
        extra.insert(
            "uriTemplate".to_string(),
            JsonVal::Str("fss://extra".to_string()),
        );
        extra.insert("owner".to_string(), JsonVal::Str("fss-extra".to_string()));
        extra.insert(
            "payloadSchema".to_string(),
            JsonVal::Str("fss.extra.v1".to_string()),
        );
        extra.insert(
            "compatibilityClass".to_string(),
            JsonVal::Str("backward_compatible".to_string()),
        );
        extra.insert("status".to_string(), JsonVal::Str("specified".to_string()));
        res.push(JsonVal::Obj(extra));
    }
    let res = validate_frozen_registry_against_compiled(&json_val);
    match res {
        Err(err) => assert!(err.contains("resource count mismatch")),
        Ok(()) => return Err("expected validation error but got Ok(())".into()),
    }
    Ok(())
}
