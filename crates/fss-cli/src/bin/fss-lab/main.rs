#![forbid(unsafe_code)]

mod digest;
mod effects;
mod ledger;
mod scenario;
mod spool;

use std::env;
use std::process::ExitCode;

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
    match run(env::args().skip(1).collect()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fss-lab: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(arguments: Vec<String>) -> Result<String, String> {
    match arguments.as_slice() {
        [] | [value] if value == "help" || value == "--help" || value == "-h" => {
            Ok(help_text().to_owned())
        }
        [command] if command == "list" => Ok(render_scenario_list()),
        [command] if command == "matrix" => render_matrix(),
        [command] if command == "self-test" => self_test(),
        [command, scenario] if command == "run" => {
            let scenario = ScenarioKind::parse(scenario).map_err(|error| error.to_string())?;
            run_scenario(scenario)
                .map(|report| report.render_json())
                .map_err(|error| error.to_string())
        }
        [command, scenario] if command == "replay" => replay(scenario, 2),
        [command, scenario, repeat_flag, repeat]
            if command == "replay" && repeat_flag == "--repeat" =>
        {
            let repeat = repeat
                .parse::<usize>()
                .map_err(|_| "--repeat requires a positive integer".to_owned())?;
            replay(scenario, repeat)
        }
        _ => Err(format!("invalid arguments\n\n{}", help_text())),
    }
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
        assert_eq!(render_matrix().expect("first"), render_matrix().expect("second"));
        assert!(self_test().expect("self-test").contains("\"status\":\"pass\""));
        assert!(replay("intrusion", 10).expect("replay").contains("\"deterministic\":true"));
    }

    #[test]
    fn replay_bounds_are_enforced() {
        assert!(replay("quiet", 1).is_err());
        assert!(replay("quiet", 10_001).is_err());
    }

    #[test]
    fn malformed_cli_is_rejected() {
        assert!(run(vec!["run".to_owned(), "unknown".to_owned()]).is_err());
        assert!(run(vec!["replay".to_owned(), "quiet".to_owned(), "--repeat".to_owned(), "x".to_owned()]).is_err());
    }
}
