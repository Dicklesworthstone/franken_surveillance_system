#![forbid(unsafe_code)]
//! Machine-checked operation registry crosswalk for FSS presentation and interface surfaces.
//!
//! Provides the total bijective mapping between registered `fss/1` operations (`AOP-001` .. `AOP-014`)
//! and their presentation surfaces across CLI commands, library entry points, and MCP tools,
//! carrying stable error identities and exit identities.

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::error::Error;

use crate::error::ExitIdentity;

/// Crosswalk mapping entry between an operation and its presentation surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationCrosswalkEntry {
    /// Stable operation identifier (e.g. `AOP-001`).
    pub operation_id: &'static str,
    /// Canonical semantic operation name (e.g. `session.open`).
    pub operation_name: &'static str,
    /// Owning subsystem crate (e.g. `fss-agent-session`).
    pub owner: &'static str,
    /// Primary CLI command invocation (e.g. `fss session open`).
    pub cli_command: &'static str,
    /// Primary Rust library entry point (e.g. `fss_agent_session::session_open`).
    pub library_entry_point: &'static str,
    /// Primary MCP tool name (e.g. `session_open`).
    pub mcp_tool_name: &'static str,
    /// Primary stable error identifier (e.g. `ERR-AUTH-DENIED-001`).
    pub primary_error_id: &'static str,
    /// Relevant registered stable error identities for this operation.
    pub error_identities: &'static [&'static str],
    /// Valid exit identities for command-line execution.
    pub exit_identities: &'static [ExitIdentity],
    /// Specification status (e.g. `specified`).
    pub status: &'static str,
}

/// The complete canonical crosswalk for all 14 registered `fss/1` operations.
pub static REGISTERED_OPERATION_CROSSWALK: &[OperationCrosswalkEntry] = &[
    OperationCrosswalkEntry {
        operation_id: "AOP-001",
        operation_name: "session.open",
        owner: "fss-agent-session",
        cli_command: "fss session open",
        library_entry_point: "fss_agent_session::session_open",
        mcp_tool_name: "session_open",
        primary_error_id: "ERR-AUTH-DENIED-001",
        error_identities: &[
            "ERR-AUTH-DENIED-001",
            "ERR-AGENT-SESSION-STALE-001",
            "ERR-BUDGET-EXHAUSTED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-002",
        operation_name: "session.resume",
        owner: "fss-agent-session",
        cli_command: "fss session resume",
        library_entry_point: "fss_agent_session::session_resume",
        mcp_tool_name: "session_resume",
        primary_error_id: "ERR-AGENT-HANDOFF-INVALID-001",
        error_identities: &[
            "ERR-AGENT-HANDOFF-INVALID-001",
            "ERR-AGENT-SESSION-STALE-001",
            "ERR-AGENT-RESUME-INDETERMINATE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-003",
        operation_name: "session.orient",
        owner: "fss-situation",
        cli_command: "fss session orient",
        library_entry_point: "fss_situation::session_orient",
        mcp_tool_name: "session_orient",
        primary_error_id: "ERR-AGENT-CONTEXT-INCOMPLETE-001",
        error_identities: &[
            "ERR-AGENT-CONTEXT-INCOMPLETE-001",
            "ERR-AGENT-SESSION-STALE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-BUDGET-EXHAUSTED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-004",
        operation_name: "session.follow",
        owner: "fss-context-pack",
        cli_command: "fss session follow",
        library_entry_point: "fss_context_pack::session_follow",
        mcp_tool_name: "session_follow",
        primary_error_id: "ERR-AGENT-RESNAPSHOT-001",
        error_identities: &[
            "ERR-AGENT-RESNAPSHOT-001",
            "ERR-AGENT-SESSION-STALE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-STREAM-CONTINUITY-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-005",
        operation_name: "query",
        owner: "fss-query-plan",
        cli_command: "fss query",
        library_entry_point: "fss_query_plan::query",
        mcp_tool_name: "query",
        primary_error_id: "ERR-AGENT-AMBIGUOUS-001",
        error_identities: &[
            "ERR-AGENT-AMBIGUOUS-001",
            "ERR-AGENT-CONTEXT-INCOMPLETE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-BUDGET-EXHAUSTED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-006",
        operation_name: "investigate",
        owner: "fss-investigation",
        cli_command: "fss investigate",
        library_entry_point: "fss_investigation::investigate",
        mcp_tool_name: "investigate",
        primary_error_id: "ERR-AGENT-CASE-BUDGET-001",
        error_identities: &[
            "ERR-AGENT-CASE-BUDGET-001",
            "ERR-AGENT-AMBIGUOUS-001",
            "ERR-AUTH-DENIED-001",
            "ERR-BUDGET-EXHAUSTED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-007",
        operation_name: "plan",
        owner: "fss-agent-plan",
        cli_command: "fss plan",
        library_entry_point: "fss_agent_plan::plan",
        mcp_tool_name: "plan",
        primary_error_id: "ERR-PRECONDITION-STALE-001",
        error_identities: &[
            "ERR-PRECONDITION-STALE-001",
            "ERR-AGENT-NO-AFFORDANCE-001",
            "ERR-AGENT-AFFORDANCE-INVALIDATED-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-008",
        operation_name: "commit",
        owner: "fss-effect",
        cli_command: "fss commit",
        library_entry_point: "fss_effect::commit",
        mcp_tool_name: "commit",
        primary_error_id: "ERR-EFFECT-INDETERMINATE-001",
        error_identities: &[
            "ERR-EFFECT-INDETERMINATE-001",
            "ERR-IDEMPOTENCY-CONFLICT-001",
            "ERR-LEASE-STALE-001",
            "ERR-PRECONDITION-STALE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-009",
        operation_name: "wait",
        owner: "fss-obligation",
        cli_command: "fss wait",
        library_entry_point: "fss_obligation::wait",
        mcp_tool_name: "wait",
        primary_error_id: "ERR-OP-TIMEOUT-001",
        error_identities: &[
            "ERR-OP-TIMEOUT-001",
            "ERR-LEASE-STALE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-010",
        operation_name: "cancel",
        owner: "fss-obligation",
        cli_command: "fss cancel",
        library_entry_point: "fss_obligation::cancel",
        mcp_tool_name: "cancel",
        primary_error_id: "ERR-QUIESCENCE-001",
        error_identities: &[
            "ERR-QUIESCENCE-001",
            "ERR-LEASE-STALE-001",
            "ERR-EFFECT-INDETERMINATE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-011",
        operation_name: "explain",
        owner: "fss-explain",
        cli_command: "fss explain",
        library_entry_point: "fss_explain::explain",
        mcp_tool_name: "explain",
        primary_error_id: "ERR-REPLAY-DIVERGED-001",
        error_identities: &[
            "ERR-REPLAY-DIVERGED-001",
            "ERR-EVIDENCE-MISSING-001",
            "ERR-AUTH-DENIED-001",
            "ERR-BUDGET-EXHAUSTED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-012",
        operation_name: "handoff",
        owner: "fss-handoff",
        cli_command: "fss handoff",
        library_entry_point: "fss_handoff::handoff",
        mcp_tool_name: "handoff",
        primary_error_id: "ERR-AGENT-HANDOFF-INVALID-001",
        error_identities: &[
            "ERR-AGENT-HANDOFF-INVALID-001",
            "ERR-AGENT-SESSION-STALE-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-013",
        operation_name: "feedback",
        owner: "fss-learning",
        cli_command: "fss feedback",
        library_entry_point: "fss_learning::feedback",
        mcp_tool_name: "feedback",
        primary_error_id: "ERR-AGENT-LEARNING-UNSUPPORTED-001",
        error_identities: &[
            "ERR-AGENT-LEARNING-UNSUPPORTED-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[ExitIdentity::SUCCESS, ExitIdentity::RUNTIME_FAILURE],
        status: "specified",
    },
    OperationCrosswalkEntry {
        operation_id: "AOP-014",
        operation_name: "doctor",
        owner: "fss-doctor",
        cli_command: "fss doctor",
        library_entry_point: "fss_doctor::doctor",
        mcp_tool_name: "doctor",
        primary_error_id: "ERR-CLI-RUNTIME-FAILURE-001",
        error_identities: &[
            "ERR-CLI-RUNTIME-FAILURE-001",
            "ERR-DOCTOR-ATTENTION-REQUIRED-001",
            "ERR-DOCTOR-NOT-A-DEPLOYMENT-001",
            "ERR-CLOCK-UNCERTAIN-001",
            "ERR-STREAM-CONTINUITY-001",
            "ERR-AUTH-DENIED-001",
            "ERR-OP-EXECUTION-FAILED-001",
        ],
        exit_identities: &[
            ExitIdentity::SUCCESS,
            ExitIdentity::RUNTIME_FAILURE,
            ExitIdentity::DOCTOR_ATTENTION_REQUIRED,
            ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT,
        ],
        status: "specified",
    },
];

/// Looks up an operation crosswalk entry by its stable operation ID.
#[must_use]
pub fn lookup_by_operation_id(id: &str) -> Option<&'static OperationCrosswalkEntry> {
    REGISTERED_OPERATION_CROSSWALK
        .iter()
        .find(|e| e.operation_id == id)
}

/// Looks up an operation crosswalk entry by its canonical operation name.
#[must_use]
pub fn lookup_by_operation_name(name: &str) -> Option<&'static OperationCrosswalkEntry> {
    REGISTERED_OPERATION_CROSSWALK
        .iter()
        .find(|e| e.operation_name == name)
}

/// Looks up an operation crosswalk entry by its CLI command string.
#[must_use]
pub fn lookup_by_cli_command(cmd: &str) -> Option<&'static OperationCrosswalkEntry> {
    REGISTERED_OPERATION_CROSSWALK
        .iter()
        .find(|e| e.cli_command == cmd)
}

/// Looks up an operation crosswalk entry by its MCP tool name.
#[must_use]
pub fn lookup_by_mcp_tool_name(tool: &str) -> Option<&'static OperationCrosswalkEntry> {
    REGISTERED_OPERATION_CROSSWALK
        .iter()
        .find(|e| e.mcp_tool_name == tool)
}

/// Looks up an operation crosswalk entry by its library entry point string.
#[must_use]
pub fn lookup_by_library_entry_point(entry: &str) -> Option<&'static OperationCrosswalkEntry> {
    REGISTERED_OPERATION_CROSSWALK
        .iter()
        .find(|e| e.library_entry_point == entry)
}

/// Crosswalk mapping entry for a registered public resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCrosswalkEntry {
    /// Stable resource identifier (e.g. `ARES-001`).
    pub resource_id: &'static str,
    /// Canonical semantic resource name (e.g. `deployment.anchor`).
    pub resource_name: &'static str,
    /// Canonical URI template (e.g. `fss://deployment/{deployment}/anchor/{anchor}`).
    pub uri_template: &'static str,
    /// Owning subsystem crate (e.g. `fss-anchor`).
    pub owner: &'static str,
    /// Associated payload schema (e.g. `fss.evidence_anchor.v1`).
    pub payload_schema: &'static str,
    /// Compatibility class (e.g. `backward_compatible`).
    pub compatibility_class: &'static str,
    /// Specification status (e.g. `specified`).
    pub status: &'static str,
}

/// The complete canonical crosswalk for all 15 registered `fss/1` public resources.
pub static REGISTERED_RESOURCE_CROSSWALK: &[ResourceCrosswalkEntry] = &[
    ResourceCrosswalkEntry {
        resource_id: "ARES-001",
        resource_name: "deployment.anchor",
        uri_template: "fss://deployment/{deployment}/anchor/{anchor}",
        owner: "fss-anchor",
        payload_schema: "fss.evidence_anchor.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-002",
        resource_name: "deployment.situation",
        uri_template: "fss://deployment/{deployment}/situation/{capsule}",
        owner: "fss-situation",
        payload_schema: "fss.situation_capsule.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-003",
        resource_name: "deployment.sensor",
        uri_template: "fss://deployment/{deployment}/sensor/{sensor}",
        owner: "fss-sensor",
        payload_schema: "fss.sensor_capsule.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-004",
        resource_name: "deployment.zone",
        uri_template: "fss://deployment/{deployment}/zone/{zone}",
        owner: "fss-zone",
        payload_schema: "fss.agent_situation_frame.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-005",
        resource_name: "deployment.event_revision",
        uri_template: "fss://deployment/{deployment}/event/{event}/revision/{revision}",
        owner: "fss-event",
        payload_schema: "fss.event_hypothesis.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-006",
        resource_name: "deployment.case_revision",
        uri_template: "fss://deployment/{deployment}/case/{case}/revision/{revision}",
        owner: "fss-investigation",
        payload_schema: "fss.investigation_state.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-007",
        resource_name: "deployment.hypothesis",
        uri_template: "fss://deployment/{deployment}/hypothesis/{hypothesis}",
        owner: "fss-investigation",
        payload_schema: "fss.agent_hypothesis_workspace.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-008",
        resource_name: "deployment.evidence",
        uri_template: "fss://deployment/{deployment}/evidence/{digest}",
        owner: "fss-evidence",
        payload_schema: "fss.evidence_bundle.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-009",
        resource_name: "deployment.plan",
        uri_template: "fss://deployment/{deployment}/plan/{plan}",
        owner: "fss-agent-plan",
        payload_schema: "fss.agent_control_plan.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-010",
        resource_name: "deployment.obligation",
        uri_template: "fss://deployment/{deployment}/obligation/{obligation}",
        owner: "fss-obligation",
        payload_schema: "fss.prepared_effect.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-011",
        resource_name: "mission.revision",
        uri_template: "fss://mission/{mission}/revision/{revision}",
        owner: "fss-mission",
        payload_schema: "fss.agent_mission.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-012",
        resource_name: "session.workspace",
        uri_template: "fss://session/{session}/workspace/{workspace}",
        owner: "fss-agent-session",
        payload_schema: "fss.agent_session_capsule.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-013",
        resource_name: "session.handoff",
        uri_template: "fss://session/{session}/handoff/{root}",
        owner: "fss-handoff",
        payload_schema: "fss.agent_handoff_capsule.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-014",
        resource_name: "experience",
        uri_template: "fss://experience/{capsule}",
        owner: "fss-learning",
        payload_schema: "fss.experience_capsule.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
    ResourceCrosswalkEntry {
        resource_id: "ARES-015",
        resource_name: "doctor",
        uri_template: "fss://doctor/{bundle}",
        owner: "fss-doctor",
        payload_schema: "fss.doctor.v1",
        compatibility_class: "backward_compatible",
        status: "specified",
    },
];

/// Looks up a resource crosswalk entry by its stable resource ID.
#[must_use]
pub fn lookup_resource_by_id(id: &str) -> Option<&'static ResourceCrosswalkEntry> {
    REGISTERED_RESOURCE_CROSSWALK
        .iter()
        .find(|e| e.resource_id == id)
}

/// Looks up a resource crosswalk entry by its canonical resource name.
#[must_use]
pub fn lookup_resource_by_name(name: &str) -> Option<&'static ResourceCrosswalkEntry> {
    REGISTERED_RESOURCE_CROSSWALK
        .iter()
        .find(|e| e.resource_name == name)
}

/// Looks up a resource crosswalk entry by its URI template.
#[must_use]
pub fn lookup_resource_by_uri_template(uri: &str) -> Option<&'static ResourceCrosswalkEntry> {
    REGISTERED_RESOURCE_CROSSWALK
        .iter()
        .find(|e| e.uri_template == uri)
}

/// Errors produced during crosswalk integrity validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrosswalkValidationError {
    /// The crosswalk registry slice is empty.
    EmptyRegistry,
    /// An operation is missing one of its required surface mappings.
    MissingSurfaceMapping {
        /// The operation ID missing a mapping.
        operation_id: String,
        /// The missing surface field name.
        surface: &'static str,
    },
    /// Two operations collide on the same CLI command.
    CliCommandCollision {
        /// The colliding CLI command.
        command: String,
        /// First operation ID.
        first_id: String,
        /// Second operation ID.
        second_id: String,
    },
    /// Two operations collide on the same MCP tool name.
    McpToolCollision {
        /// The colliding MCP tool name.
        tool_name: String,
        /// First operation ID.
        first_id: String,
        /// Second operation ID.
        second_id: String,
    },
    /// Two operations collide on the same library entry point.
    LibraryEntryCollision {
        /// The colliding library entry point.
        entry_point: String,
        /// First operation ID.
        first_id: String,
        /// Second operation ID.
        second_id: String,
    },
    /// An operation maps an unregistered or uncertified error code.
    UnregisteredError {
        /// The operation ID referencing the error.
        operation_id: String,
        /// The invalid error identifier.
        error_id: String,
    },
    /// An operation references an invalid exit identity.
    InvalidExitIdentity {
        /// The operation ID.
        operation_id: String,
        /// The invalid exit identity string.
        identity: String,
    },
    /// Stale or tombstoned entry detected in an active crosswalk mapping.
    StaleEntry {
        /// The operation ID.
        operation_id: String,
        /// Rationale for failure.
        reason: String,
    },
    /// Duplicate operation ID detected in the crosswalk registry.
    DuplicateOperation {
        /// The duplicate operation ID.
        operation_id: String,
    },
}

impl fmt::Display for CrosswalkValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRegistry => write!(f, "operation crosswalk registry is empty"),
            Self::MissingSurfaceMapping {
                operation_id,
                surface,
            } => {
                write!(
                    f,
                    "operation '{operation_id}' missing mandatory surface mapping '{surface}'"
                )
            }
            Self::CliCommandCollision {
                command,
                first_id,
                second_id,
            } => {
                write!(
                    f,
                    "CLI command '{command}' collision between '{first_id}' and '{second_id}'"
                )
            }
            Self::McpToolCollision {
                tool_name,
                first_id,
                second_id,
            } => {
                write!(
                    f,
                    "MCP tool name '{tool_name}' collision between '{first_id}' and '{second_id}'"
                )
            }
            Self::LibraryEntryCollision {
                entry_point,
                first_id,
                second_id,
            } => {
                write!(
                    f,
                    "library entry point '{entry_point}' collision between '{first_id}' and '{second_id}'"
                )
            }
            Self::UnregisteredError {
                operation_id,
                error_id,
            } => {
                write!(
                    f,
                    "operation '{operation_id}' references unregistered error code '{error_id}'"
                )
            }
            Self::InvalidExitIdentity {
                operation_id,
                identity,
            } => {
                write!(
                    f,
                    "operation '{operation_id}' references invalid exit identity '{identity}'"
                )
            }
            Self::StaleEntry {
                operation_id,
                reason,
            } => {
                write!(f, "operation '{operation_id}' is stale: {reason}")
            }
            Self::DuplicateOperation { operation_id } => {
                write!(f, "duplicate operation ID '{operation_id}' in crosswalk")
            }
        }
    }
}

impl Error for CrosswalkValidationError {}

/// Canonical registered process exit identities matching `registries/ERRORS.md`.
pub static REGISTERED_EXIT_IDENTITIES: &[&str] = &[
    "EXIT-OK-000",
    "EXIT-CLI-RUNTIME-FAILURE-001",
    "EXIT-CLI-UNKNOWN-COMMAND-002",
    "EXIT-CLI-UNKNOWN-OPTION-002",
    "EXIT-CLI-MISSING-VALUE-002",
    "EXIT-CLI-DUPLICATE-OPTION-002",
    "EXIT-CLI-MALFORMED-VALUE-002",
    "EXIT-CLI-INVALID-UNICODE-002",
    "EXIT-CLI-UNEXPECTED-POSITIONAL-002",
    "EXIT-CLI-TRAILING-ARGUMENT-002",
    "EXIT-DOCTOR-ATTENTION-REQUIRED-003",
    "EXIT-DOCTOR-NOT-A-DEPLOYMENT-004",
];

fn normalize_identifier(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_was_sep = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_was_sep = false;
        } else if !prev_was_sep && !out.is_empty() {
            out.push('_');
            prev_was_sep = true;
        }
    }
    if out.ends_with('_') {
        out.pop();
    }
    out
}

fn normalize_cli_command(cmd: &str) -> String {
    cmd.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Validates that a given slice of crosswalk entries is well-formed, bijective, and collision-free.
pub fn validate_crosswalk_entries(
    entries: &[OperationCrosswalkEntry],
    allowed_error_ids: &[&str],
) -> Result<(), CrosswalkValidationError> {
    if entries.is_empty() {
        return Err(CrosswalkValidationError::EmptyRegistry);
    }

    let mut op_ids: HashSet<&str> = HashSet::new();
    let mut cli_map: HashMap<String, &'static str> = HashMap::new();
    let mut mcp_map: HashMap<String, &'static str> = HashMap::new();
    let mut lib_map: HashMap<String, &'static str> = HashMap::new();

    let allowed_set: HashSet<&str> = allowed_error_ids.iter().copied().collect();

    for entry in entries {
        if !op_ids.insert(entry.operation_id) {
            return Err(CrosswalkValidationError::DuplicateOperation {
                operation_id: entry.operation_id.to_string(),
            });
        }

        if entry.status == "tombstone" || entry.status == "deprecated" {
            return Err(CrosswalkValidationError::StaleEntry {
                operation_id: entry.operation_id.to_string(),
                reason: format!("operation has status '{}'", entry.status),
            });
        }

        if entry.cli_command.trim().is_empty() {
            return Err(CrosswalkValidationError::MissingSurfaceMapping {
                operation_id: entry.operation_id.to_string(),
                surface: "cli_command",
            });
        }
        if entry.mcp_tool_name.trim().is_empty() {
            return Err(CrosswalkValidationError::MissingSurfaceMapping {
                operation_id: entry.operation_id.to_string(),
                surface: "mcp_tool_name",
            });
        }
        if entry.library_entry_point.trim().is_empty() {
            return Err(CrosswalkValidationError::MissingSurfaceMapping {
                operation_id: entry.operation_id.to_string(),
                surface: "library_entry_point",
            });
        }
        if entry.primary_error_id.trim().is_empty() {
            return Err(CrosswalkValidationError::MissingSurfaceMapping {
                operation_id: entry.operation_id.to_string(),
                surface: "primary_error_id",
            });
        }

        let norm_cli = normalize_cli_command(entry.cli_command);
        if let Some(first_id) = cli_map.get(&norm_cli) {
            return Err(CrosswalkValidationError::CliCommandCollision {
                command: entry.cli_command.to_string(),
                first_id: (*first_id).to_string(),
                second_id: entry.operation_id.to_string(),
            });
        }
        let curr_tokens: Vec<&str> = norm_cli.split_whitespace().collect();
        for (prev_cmd, prev_id) in &cli_map {
            let prev_tokens: Vec<&str> = prev_cmd.split_whitespace().collect();
            if (curr_tokens.len() < prev_tokens.len() && prev_tokens.starts_with(&curr_tokens))
                || (prev_tokens.len() < curr_tokens.len() && curr_tokens.starts_with(&prev_tokens))
            {
                return Err(CrosswalkValidationError::CliCommandCollision {
                    command: entry.cli_command.to_string(),
                    first_id: (*prev_id).to_string(),
                    second_id: entry.operation_id.to_string(),
                });
            }
        }
        cli_map.insert(norm_cli, entry.operation_id);

        let norm_mcp = normalize_identifier(entry.mcp_tool_name);
        if let Some(first_id) = mcp_map.get(&norm_mcp) {
            return Err(CrosswalkValidationError::McpToolCollision {
                tool_name: entry.mcp_tool_name.to_string(),
                first_id: (*first_id).to_string(),
                second_id: entry.operation_id.to_string(),
            });
        }
        mcp_map.insert(norm_mcp, entry.operation_id);

        let norm_lib = normalize_identifier(entry.library_entry_point);
        if let Some(first_id) = lib_map.get(&norm_lib) {
            return Err(CrosswalkValidationError::LibraryEntryCollision {
                entry_point: entry.library_entry_point.to_string(),
                first_id: (*first_id).to_string(),
                second_id: entry.operation_id.to_string(),
            });
        }
        lib_map.insert(norm_lib, entry.operation_id);

        if !entry.primary_error_id.starts_with("ERR-") {
            return Err(CrosswalkValidationError::UnregisteredError {
                operation_id: entry.operation_id.to_string(),
                error_id: entry.primary_error_id.to_string(),
            });
        }
        if !allowed_set.is_empty() && !allowed_set.contains(entry.primary_error_id) {
            return Err(CrosswalkValidationError::UnregisteredError {
                operation_id: entry.operation_id.to_string(),
                error_id: entry.primary_error_id.to_string(),
            });
        }

        if entry.error_identities.is_empty() {
            return Err(CrosswalkValidationError::MissingSurfaceMapping {
                operation_id: entry.operation_id.to_string(),
                surface: "error_identities",
            });
        }
        for err in entry.error_identities {
            if !err.starts_with("ERR-") {
                return Err(CrosswalkValidationError::UnregisteredError {
                    operation_id: entry.operation_id.to_string(),
                    error_id: (*err).to_string(),
                });
            }
            if !allowed_set.is_empty() && !allowed_set.contains(err) {
                return Err(CrosswalkValidationError::UnregisteredError {
                    operation_id: entry.operation_id.to_string(),
                    error_id: (*err).to_string(),
                });
            }
        }

        if entry.exit_identities.is_empty() {
            return Err(CrosswalkValidationError::MissingSurfaceMapping {
                operation_id: entry.operation_id.to_string(),
                surface: "exit_identities",
            });
        }
        for exit in entry.exit_identities {
            if !exit.identifier.starts_with("EXIT-")
                || !REGISTERED_EXIT_IDENTITIES.contains(&exit.identifier)
            {
                return Err(CrosswalkValidationError::InvalidExitIdentity {
                    operation_id: entry.operation_id.to_string(),
                    identity: exit.identifier.to_string(),
                });
            }
        }
    }

    Ok(())
}
