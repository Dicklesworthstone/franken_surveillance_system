#![forbid(unsafe_code)]
//! Comprehensive 14-Operation JSON-RPC 2.0 `fss-mcp` E2E, Adversarial Privacy/Capability,
//! Canary Leak-Audit, and 4-Agent × 8-Camera Concurrency Test Suite (`fss-x4a.31.4.5` / `D5`).
//!
//! Exercises the real `fss-mcp` stdio binary, live `fss-daemon` supervisor with UDS `fss-ipc`
//! and v2 pack/epoch/MVCC storage, pure-Rust RFC 8446 TLS 1.3 HMAC-SHA256 webhook receiver,
//! `fss-vault` canary secret scanning, and pure-Rust JPEG pixel-level privacy-mask verification.

use std::error::Error;
use std::sync::Mutex;

#[path = "mcp_14_ops_adversarial_e2e/fixtures.rs"]
mod fixtures;
#[path = "mcp_14_ops_adversarial_e2e/harness.rs"]
mod harness;
#[path = "mcp_14_ops_adversarial_e2e/report.rs"]
mod report;
#[path = "mcp_14_ops_adversarial_e2e/scenario1_effects.rs"]
mod scenario1_effects;
#[path = "mcp_14_ops_adversarial_e2e/scenario1_lifecycle.rs"]
mod scenario1_lifecycle;
#[path = "mcp_14_ops_adversarial_e2e/scenario2_adversarial.rs"]
mod scenario2_adversarial;
#[path = "mcp_14_ops_adversarial_e2e/scenario3_concurrency.rs"]
mod scenario3_concurrency;

/// Shared test result alias across the 14-operation MCP adversarial E2E suite.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Serializes latency-sensitive E2E scenarios within the test binary so 4-client × 8-camera
/// stress load never starves Scenario 1's warm `< 10ms` p99 `session_orient` measurement.
static SUITE_SERIAL: Mutex<()> = Mutex::new(());

fn with_serial_guard<F>(body: F) -> TestResult
where
    F: FnOnce() -> TestResult,
{
    let _guard = SUITE_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    body()
}

#[test]
fn scenario_1_full_14_tool_lifecycle_against_live_daemon() -> TestResult {
    with_serial_guard(|| {
        let outcome = scenario1_lifecycle::run()?;
        report::record_scenario_1(outcome)?;
        Ok(())
    })
}

#[test]
fn scenario_2_adversarial_privacy_mask_capability_and_canary_gauntlet() -> TestResult {
    with_serial_guard(|| {
        let outcome = scenario2_adversarial::run()?;
        report::record_scenario_2(outcome)?;
        Ok(())
    })
}

#[test]
fn scenario_3_concurrent_4_agents_vs_live_8_camera_daemon_stress() -> TestResult {
    with_serial_guard(|| {
        let outcome = scenario3_concurrency::run()?;
        report::record_scenario_3(outcome)?;
        Ok(())
    })
}
