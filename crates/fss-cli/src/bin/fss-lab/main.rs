#![forbid(unsafe_code)]
//! Deterministic reference surveillance laboratory CLI.
//!
//! Laboratory scenarios drive the real pure-Rust stack through [`ReferenceDeployment`](fss_reference::ReferenceDeployment)
//! under a caller-given `--root` directory.

mod crash_matrix;
mod file_activity;
mod scenario;

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

#[cfg(test)]
use fss_cli::{ArgToken, parse_lab_tokens};
use fss_cli::{LabAction, emit_diagnostic, lab_help_text, parse_lab_args};
use scenario::{ScenarioKind, run_scenario};

const ALL_SCENARIOS: [ScenarioKind; 6] = [
    ScenarioKind::Quiet,
    ScenarioKind::Raccoon,
    ScenarioKind::Intrusion,
    ScenarioKind::Sneaky,
    ScenarioKind::LostAcknowledgement,
    ScenarioKind::CorruptSource,
];

fn main() -> ExitCode {
    match parse_lab_args(env::args_os().skip(1)) {
        Ok(action) => match run_action(action) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fss-lab: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            emit_diagnostic(&error, "fss-lab", None);
            ExitCode::from(error.exit_identity().code)
        }
    }
}

fn run_action(action: LabAction) -> Result<String, String> {
    match action {
        LabAction::Help => Ok(lab_help_text().to_owned()),
        LabAction::List => Ok(render_scenario_list()),
        LabAction::Matrix { root } => {
            check_root_empty(&root)?;
            render_matrix(&root)
        }
        LabAction::SelfTest { root } => {
            check_root_empty(&root)?;
            self_test(&root)
        }
        LabAction::Run { scenario, root } => {
            check_root_empty(&root)?;
            let scenario = ScenarioKind::parse(&scenario).map_err(|error| error.to_string())?;
            run_scenario(scenario, &root)
                .map(|report| report.render_json())
                .map_err(|error| error.to_string())
        }
        LabAction::Replay {
            scenario,
            repeat,
            root,
        } => {
            check_root_empty(&root)?;
            replay(&scenario, repeat, &root)
        }
        LabAction::CrashMatrix {
            root,
            scenario,
            json,
        } => {
            check_root_empty(&root)?;
            crash_matrix_command(&scenario, json, &root)
        }
    }
}

/// Runs the crash matrix. A failing verdict is still reported in full on stdout, and the command
/// then exits non-zero.
fn crash_matrix_command(scenario: &str, json: bool, root: &Path) -> Result<String, String> {
    if scenario != crash_matrix::MATRIX_SCENARIO.as_str() {
        return Err(format!(
            "crash-matrix has an expected-class table only for {}",
            crash_matrix::MATRIX_SCENARIO.as_str()
        ));
    }
    let rows = crash_matrix::run_matrix(root)?;
    let rendered = if json {
        crash_matrix::render_json(&rows)
    } else {
        crash_matrix::render_text(&rows)
    };
    if crash_matrix::verdict(&rows) {
        Ok(rendered)
    } else {
        println!("{rendered}");
        Err(format!(
            "crash matrix verdict fail: {} of {} rows differ from the documented recovery contract",
            rows.iter().filter(|row| !row.passes()).count(),
            rows.len()
        ))
    }
}

fn check_root_empty(root: &Path) -> Result<(), String> {
    if root.exists() {
        if !root.is_dir() {
            return Err(format!(
                "ERR-LAB-ROOT-NOT-EMPTY-001: root_not_empty: target root is not a directory: {}",
                root.display()
            ));
        }
        let mut read_dir =
            fs::read_dir(root).map_err(|err| format!("io error reading root: {err}"))?;
        if let Some(entry) = read_dir.next() {
            let _ = entry.map_err(|err| format!("io error reading root entry: {err}"))?;
            return Err(format!(
                "ERR-LAB-ROOT-NOT-EMPTY-001: root_not_empty: target root directory is not empty: {}",
                root.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn run(arguments: Vec<String>) -> Result<String, String> {
    let tokens: Vec<ArgToken> = arguments
        .into_iter()
        .enumerate()
        .map(|(index, raw)| ArgToken::new(index, raw))
        .collect();
    let action = parse_lab_tokens(&tokens).map_err(|error| error.to_string())?;
    run_action(action)
}

fn render_scenario_list() -> String {
    let mut output = String::from("{\"schema\":\"fss.lab.scenarios.v1\",\"scenarios\":[");
    for (index, scenario) in ALL_SCENARIOS.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('"');
        output.push_str(scenario.as_str());
        output.push('"');
    }
    output.push_str("]}");
    output
}

fn render_matrix(root: &Path) -> Result<String, String> {
    let mut output = String::from("{\"schema\":\"fss.lab.matrix.v1\",\"reports\":[");
    for (index, scenario) in ALL_SCENARIOS.iter().copied().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let scenario_root = root.join(scenario.as_str());
        output.push_str(
            &run_scenario(scenario, &scenario_root)
                .map_err(|error| error.to_string())?
                .render_json(),
        );
    }
    output.push_str("]}");
    Ok(output)
}

fn replay(scenario: &str, repeat: usize, root: &Path) -> Result<String, String> {
    if repeat < 2 {
        return Err("replay requires --repeat >= 2".to_owned());
    }
    if repeat > 10_000 {
        return Err("replay repeat count exceeds the 10000-run bound".to_owned());
    }
    let scenario = ScenarioKind::parse(scenario).map_err(|error| error.to_string())?;
    let run_0_root = root.join("run-0");
    let expected = run_scenario(scenario, &run_0_root)
        .map_err(|error| error.to_string())?
        .render_json();
    for iteration in 1..repeat {
        let run_i_root = root.join(format!("run-{iteration}"));
        let observed = run_scenario(scenario, &run_i_root)
            .map_err(|error| error.to_string())?
            .render_json();
        if observed != expected {
            return Err(format!(
                "deterministic replay diverged at iteration {}",
                iteration + 1
            ));
        }
    }
    let mut encoder = fss_core::CanonicalEncoder::new();
    encoder.text("fss.lab.replay.transcript.v1");
    encoder.bytes(expected.as_bytes());
    let digest = fss_core::ContentDigest::sha256(&encoder.finish()).to_string();

    Ok(format!(
        "{{\"schema\":\"fss.lab.replay.v1\",\"scenario\":\"{}\",\"runs\":{},\"deterministic\":true,\"transcript_digest\":\"{}\",\"report\":{}}}",
        scenario.as_str(),
        repeat,
        digest,
        expected
    ))
}

fn self_test(root: &Path) -> Result<String, String> {
    let first = render_matrix(&root.join("test-1"))?;
    let second = render_matrix(&root.join("test-2"))?;
    if first != second {
        return Err("scenario matrix is not deterministic".to_owned());
    }
    let mut encoder = fss_core::CanonicalEncoder::new();
    encoder.text("fss.lab.self_test.matrix.v1");
    encoder.bytes(first.as_bytes());
    let digest = fss_core::ContentDigest::sha256(&encoder.finish()).to_string();

    Ok(format!(
        "{{\"schema\":\"fss.lab.self_test.v1\",\"status\":\"pass\",\"scenario_count\":{},\"matrix_digest\":\"{}\"}}",
        ALL_SCENARIOS.len(),
        digest
    ))
}

#[cfg(test)]
mod tests {
    use super::{render_matrix, replay, run, self_test};

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fss-lab-main-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn public_commands_are_deterministic() {
        let root_mat = temp_root("mat");
        let first = render_matrix(&root_mat.join("m1"));
        let second = render_matrix(&root_mat.join("m2"));
        assert!(first.is_ok());
        assert!(second.is_ok());
        if let (Ok(f), Ok(s)) = (first, second) {
            assert_eq!(f, s);
        }
        let root_st = temp_root("st");
        let st = self_test(&root_st);
        assert!(st.is_ok());
        if let Ok(text) = st {
            assert!(text.contains("\"status\":\"pass\""));
        }
        let root_rep = temp_root("rep");
        let rep = replay("intrusion", 3, &root_rep);
        assert!(rep.is_ok());
        if let Ok(text) = rep {
            assert!(text.contains("\"deterministic\":true"));
        }
        let _ = std::fs::remove_dir_all(&root_mat);
        let _ = std::fs::remove_dir_all(&root_st);
        let _ = std::fs::remove_dir_all(&root_rep);
    }

    /// SHA-256 and length of the exact `fss-lab matrix` stdout line (without the trailing
    /// newline) produced by origin/main d958255, before the executor-backed observation
    /// variant existed (fss-2h5zq.51; the `lab_matrix_baseline_sha256` of fss-2h5zq.12).
    const MAIN_MATRIX_SHA256: &str =
        "sha256:aa5923d94cc427c524c0d2172cbf53a91fb8c4c81f77c073949284e463c8ac0e";
    const MAIN_MATRIX_BYTES: usize = 8621;

    #[test]
    fn six_mock_scenario_matrix_is_byte_identical_to_main() {
        let root = temp_root("mat-baseline");
        let matrix = render_matrix(&root);
        let _ = std::fs::remove_dir_all(&root);
        let matrix = matrix.unwrap_or_default();
        assert_eq!(matrix.len(), MAIN_MATRIX_BYTES);
        assert_eq!(
            fss_core::ContentDigest::sha256(matrix.as_bytes()).to_string(),
            MAIN_MATRIX_SHA256
        );
        assert!(!matrix.contains("file-activity"));
        assert!(!matrix.contains("\"executor\""));
    }

    #[test]
    fn file_activity_runs_and_replays_but_stays_out_of_the_matrix() {
        let root = temp_root("file-activity-run");
        let run_output = run(vec![
            "run".to_owned(),
            "file-activity".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ]);
        let _ = std::fs::remove_dir_all(&root);
        let report = run_output.unwrap_or_default();
        assert!(report.contains("\"scenario\":\"file-activity\""));
        assert!(report.contains("\"corroboration\":\"single_source\""));
        assert!(!report.contains("\"corroboration\":\"corroborated\""));
        assert!(report.contains("\"not_certifiable\":\"continuity_not_observable\""));
        let root = temp_root("file-activity-replay");
        let replayed = replay("file-activity", 2, &root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            replayed
                .unwrap_or_default()
                .contains("\"deterministic\":true")
        );
        let list = run(vec!["list".to_owned()]).unwrap_or_default();
        assert!(!list.contains("file-activity"));
    }

    #[test]
    fn replay_bounds_are_enforced() {
        let root = temp_root("rep-bounds");
        assert!(replay("quiet", 1, &root).is_err());
        assert!(replay("quiet", 10_001, &root).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_cli_is_rejected() {
        assert!(
            run(vec![
                "run".to_owned(),
                "unknown".to_owned(),
                "--root".to_owned(),
                "/tmp/fss-lab-dummy".to_owned()
            ])
            .is_err()
        );
        assert!(
            run(vec![
                "replay".to_owned(),
                "quiet".to_owned(),
                "--root".to_owned(),
                "/tmp/fss-lab-dummy".to_owned(),
                "--repeat".to_owned(),
                "x".to_owned()
            ])
            .is_err()
        );
    }
}
