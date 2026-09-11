#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Deterministic reference surveillance laboratory CLI.

mod digest;
mod effects;
mod ledger;
mod scenario;
mod spool;

use std::env;
use std::process::ExitCode;

#[cfg(test)]
use fss_cli::{ArgToken, parse_lab_tokens};
use fss_cli::{LabAction, emit_diagnostic, parse_lab_args};
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
        LabAction::Help => Ok(help_text().to_owned()),
        LabAction::List => Ok(render_scenario_list()),
        LabAction::Matrix => render_matrix(),
        LabAction::SelfTest => self_test(),
        LabAction::Run { scenario } => {
            let scenario = ScenarioKind::parse(&scenario).map_err(|error| error.to_string())?;
            run_scenario(scenario)
                .map(|report| report.render_json())
                .map_err(|error| error.to_string())
        }
        LabAction::Replay { scenario, repeat } => replay(&scenario, repeat),
    }
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

fn render_matrix() -> Result<String, String> {
    let mut output = String::from("{\"schema\":\"fss.lab.matrix.v1\",\"reports\":[");
    for (index, scenario) in ALL_SCENARIOS.iter().copied().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(
            &run_scenario(scenario)
                .map_err(|error| error.to_string())?
                .render_json(),
        );
    }
    output.push_str("]}");
    Ok(output)
}

fn replay(scenario: &str, repeat: usize) -> Result<String, String> {
    if repeat < 2 {
        return Err("replay requires --repeat >= 2".to_owned());
    }
    if repeat > 10_000 {
        return Err("replay repeat count exceeds the 10000-run bound".to_owned());
    }
    let scenario = ScenarioKind::parse(scenario).map_err(|error| error.to_string())?;
    let expected = run_scenario(scenario)
        .map_err(|error| error.to_string())?
        .render_json();
    for iteration in 1..repeat {
        let observed = run_scenario(scenario)
            .map_err(|error| error.to_string())?
            .render_json();
        if observed != expected {
            return Err(format!(
                "deterministic replay diverged at iteration {}",
                iteration + 1
            ));
        }
    }
    let digest = digest::domain_digest("fss-lab-replay-transcript-v1", expected.as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"schema\":\"fss.lab.replay.v1\",\"scenario\":\"{}\",\"runs\":{},\"deterministic\":true,\"transcript_digest\":\"{}\",\"report\":{}}}",
        scenario.as_str(),
        repeat,
        digest,
        expected
    ))
}

fn self_test() -> Result<String, String> {
    let first = render_matrix()?;
    let second = render_matrix()?;
    if first != second {
        return Err("scenario matrix is not deterministic".to_owned());
    }
    let digest = digest::domain_digest("fss-lab-self-test-v1", first.as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"schema\":\"fss.lab.self_test.v1\",\"status\":\"pass\",\"scenario_count\":{},\"matrix_digest\":\"{}\"}}",
        ALL_SCENARIOS.len(),
        digest
    ))
}

const fn help_text() -> &'static str {
    "fss-lab — deterministic reference surveillance laboratory\n\n\
USAGE\n  fss-lab list\n  fss-lab run <scenario>\n  fss-lab matrix\n  fss-lab replay <scenario> [--repeat N]\n  fss-lab self-test\n\n\
SCENARIOS\n  quiet           complete coverage and a certified absence\n  raccoon         benign wildlife with no alert effect\n  intrusion       independently corroborated person and verified alert\n  sneaky          material person residual plus an observability gap\n  lost-ack        indeterminate alert dispatch resolved by reconciliation\n  corrupt-source  source corruption detected before evidence publication\n"
}

#[cfg(test)]
mod tests {
    use super::{render_matrix, replay, run, self_test};

    #[test]
    fn public_commands_are_deterministic() {
        let first = render_matrix();
        let second = render_matrix();
        assert!(first.is_ok());
        assert!(second.is_ok());
        if let (Ok(f), Ok(s)) = (first, second) {
            assert_eq!(f, s);
        }
        let st = self_test();
        assert!(st.is_ok());
        if let Ok(text) = st {
            assert!(text.contains("\"status\":\"pass\""));
        }
        let rep = replay("intrusion", 10);
        assert!(rep.is_ok());
        if let Ok(text) = rep {
            assert!(text.contains("\"deterministic\":true"));
        }
    }

    #[test]
    fn replay_bounds_are_enforced() {
        assert!(replay("quiet", 1).is_err());
        assert!(replay("quiet", 10_001).is_err());
    }

    #[test]
    fn malformed_cli_is_rejected() {
        assert!(run(vec!["run".to_owned(), "unknown".to_owned()]).is_err());
        assert!(
            run(vec![
                "replay".to_owned(),
                "quiet".to_owned(),
                "--repeat".to_owned(),
                "x".to_owned()
            ])
            .is_err()
        );
    }
}
