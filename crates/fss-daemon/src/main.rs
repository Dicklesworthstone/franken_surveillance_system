#![forbid(unsafe_code)]
//! Standalone always-on multi-camera daemon binary (`fss-daemon`).
//!
//! Semantic plane: `"authority"`.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use fss_core::PrincipalId;
use fss_daemon::{
    DaemonStartConfig, DaemonSupervisor, SensorHealthPolicy, SiteManifest, escape_json,
    query_camera_retention_forecast, query_live_daemon_status, render_live_status_json, render_stop_accepted_json,
    request_live_daemon_stop,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        println!("{}", help_text());
        return ExitCode::SUCCESS;
    }
    if matches!(args[0].as_str(), "version" | "--version" | "-V") {
        println!("fss-daemon {VERSION}");
        return ExitCode::SUCCESS;
    }

    match args[0].as_str() {
        "run" => run_cmd(&args[1..]),
        "status" => status_cmd(&args[1..]),
        "retention-forecast" => retention_forecast_cmd(&args[1..]),
        "stop" => stop_cmd(&args[1..]),
        other => {
            eprintln!("ERR-DAEMON-MANIFEST-INVALID-001: unknown subcommand `{other}`");
            ExitCode::from(2)
        }
    }
}

const FORBIDDEN_ARGV_SECRET_FLAGS: &[&str] = &[
    "--passphrase",
    "--password",
    "--secret",
    "--token",
    "--api-key",
];

fn run_cmd(args: &[String]) -> ExitCode {
    let mut manifest_path: Option<PathBuf> = None;
    let mut root_override: Option<PathBuf> = None;
    let mut vault_dir: Option<PathBuf> = None;
    let mut vault_passphrase_file: Option<PathBuf> = None;
    let mut once_ticks: Option<u64> = None;
    let mut tick_ms: u64 = 50;
    let mut sensor_health_policy = None;
    let mut json = false;

    let mut idx = 0_usize;
    while idx < args.len() {
        let flag = args[idx]
            .split_once('=')
            .map_or(args[idx].as_str(), |(k, _)| k);
        if FORBIDDEN_ARGV_SECRET_FLAGS.contains(&flag) {
            return fail_json(
                json,
                "ERR-DAEMON-VAULT-001",
                "plaintext secrets and passphrases are forbidden on CLI argv; use --vault-dir and --passphrase-file (0600)",
            );
        }
        match args[idx].as_str() {
            "--manifest" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "missing --manifest value",
                    );
                };
                manifest_path = Some(PathBuf::from(val));
            }
            "--root" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "missing --root value",
                    );
                };
                root_override = Some(PathBuf::from(val));
            }
            "--vault-dir" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return fail_json(json, "ERR-DAEMON-VAULT-001", "missing --vault-dir value");
                };
                vault_dir = Some(PathBuf::from(val));
            }
            "--passphrase-file" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return fail_json(
                        json,
                        "ERR-DAEMON-VAULT-001",
                        "missing --passphrase-file value",
                    );
                };
                vault_passphrase_file = Some(PathBuf::from(val));
            }
            "--once-ticks" => {
                idx += 1;
                let Some(val) = args.get(idx).and_then(|s| s.parse::<u64>().ok()) else {
                    return fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "invalid --once-ticks integer",
                    );
                };
                once_ticks = Some(val);
            }
            "--sensor-health" => {
                idx += 1;
                let Some(value) = args.get(idx) else {
                    return fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "missing --sensor-health policy",
                    );
                };
                sensor_health_policy = match SensorHealthPolicy::parse(value) {
                    Ok(policy) => Some(policy),
                    Err(error) => return fail_json(json, error.error_id(), &error.to_string()),
                };
            }
            "--tick-ms" => {
                idx += 1;
                let Some(val) = args.get(idx).and_then(|s| s.parse::<u64>().ok()) else {
                    return fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "invalid --tick-ms integer",
                    );
                };
                tick_ms = val;
            }
            "--json" => json = true,
            other => {
                return fail_json(
                    json,
                    "ERR-DAEMON-MANIFEST-INVALID-001",
                    &format!("unknown option `{other}`"),
                );
            }
        }
        idx += 1;
    }

    let Some(path) = manifest_path else {
        return fail_json(
            json,
            "ERR-DAEMON-MANIFEST-INVALID-001",
            "--manifest is required",
        );
    };
    let manifest = match SiteManifest::from_file(&path) {
        Ok(m) => m,
        Err(err) => return fail_json(json, err.error_id(), &err.to_string()),
    };
    let mut cfg = DaemonStartConfig::new(manifest);
    cfg.manifest_path = Some(path);
    cfg.root_override = root_override;
    cfg.vault_dir = vault_dir;
    cfg.vault_passphrase_file = vault_passphrase_file;
    cfg.sensor_health_policy = sensor_health_policy;
    let supervisor = match DaemonSupervisor::start(cfg) {
        Ok(s) => s,
        Err(err) => return fail_json(json, err.error_id(), &err.to_string()),
    };
    let report = match supervisor.run_until_stopped(once_ticks, Duration::from_millis(tick_ms)) {
        Ok(r) => r,
        Err(err) => return fail_json(json, err.error_id(), &err.to_string()),
    };
    if json {
        println!("{}", report.to_json());
    } else {
        println!(
            "fss-daemon stopped site={} ticks={} head_seq={} active_tasks={} leaked_obligations={}",
            report.site_id,
            report.ticks_executed,
            report.head_commit_sequence,
            report.active_tasks,
            report.leaked_obligations
        );
    }
    ExitCode::SUCCESS
}

fn status_cmd(args: &[String]) -> ExitCode {
    let (root, site_id, json) = match parse_root_and_site(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Ok(principal) = PrincipalId::parse("principal:local-operator") else {
        return fail_json(json, "ERR-DAEMON-IPC-001", "invalid operator principal");
    };
    let (desc, status) = match query_live_daemon_status(&root, site_id.as_deref(), principal) {
        Ok(v) => v,
        Err(err) => return fail_json(json, err.error_id(), &err.to_string()),
    };
    if json {
        println!("{}", render_live_status_json(&desc, &status));
    } else {
        println!(
            "fss-daemon running site={} pid={} uptime_ms={} head_seq={} cameras={}",
            desc.site_id,
            desc.pid,
            status.daemon_uptime_ms,
            status.head_commit_sequence,
            status.cameras.len()
        );
    }
    ExitCode::SUCCESS
}

fn retention_forecast_cmd(args: &[String]) -> ExitCode {
    let Some((camera_id, options)) = args.split_first().filter(|(id, _)| !id.starts_with("--"))
    else {
        return fail_json(
            args.iter().any(|arg| arg == "--json"),
            "ERR-DAEMON-MANIFEST-INVALID-001",
            "retention-forecast requires a camera identifier",
        );
    };
    let (root, site_id, json) = match parse_root_and_site(options) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Ok(principal) = PrincipalId::parse("principal:local-operator") else {
        return fail_json(json, "ERR-DAEMON-IPC-001", "invalid operator principal");
    };
    let (desc, row) = match query_camera_retention_forecast(
        &root,
        site_id.as_deref(),
        principal,
        camera_id,
    ) {
        Ok(v) => v,
        Err(err) => return fail_json(json, err.error_id(), &err.to_string()),
    };
    let state = match &row.oldest {
        None => "no_recordings",
        Some(window) if window.known_pin => "pinned",
        Some(window) if window.age_deadline_ns <= row.assessed_at_ns => "age_deadline_reached",
        Some(_) => "before_age_deadline",
    };
    if json {
        let oldest = row.oldest.as_ref().map_or_else(|| "null".to_owned(), |window| {
            format!(
                "{{\"capture_start_ns\":\"{}\",\"capture_end_ns\":\"{}\",\"age_deadline_ns\":\"{}\",\"known_pin\":{}}}",
                window.capture_start_ns, window.capture_end_ns, window.age_deadline_ns, window.known_pin
            )
        });
        println!(
            concat!(
                "{{\"schema\":\"fss.daemon_retention_forecast.v1\",\"site_id\":\"{}\",\"camera_id\":\"{}\",",
                "\"assessed_at_ns\":\"{}\",\"retain_hot_ns\":{},\"max_sensor_bytes\":{},",
                "\"retained_windows\":{},\"retained_bytes\":{},\"state\":\"{}\",\"oldest\":{}}}"
            ),
            escape_json(&desc.site_id), escape_json(&row.camera_id), row.assessed_at_ns,
            row.retain_hot_ns, row.max_sensor_bytes, row.retained_windows, row.retained_bytes, state, oldest
        );
    } else {
        println!("{} retention at {} ns: {} windows, {} accounted media bytes, {} byte camera cap, state={}",
            row.camera_id, row.assessed_at_ns, row.retained_windows, row.retained_bytes, row.max_sensor_bytes, state);
        if let Some(window) = row.oldest {
            println!("Oldest capture {}..{} ns. Time-policy deadline {} ns. Byte pressure can reclaim sooner and pins can extend retention.",
                window.capture_start_ns, window.capture_end_ns, window.age_deadline_ns);
        }
    }
    ExitCode::SUCCESS
}

fn stop_cmd(args: &[String]) -> ExitCode {
    let (root, site_id, json) = match parse_root_and_site(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let Ok(principal) = PrincipalId::parse("principal:local-operator") else {
        return fail_json(json, "ERR-DAEMON-IPC-001", "invalid operator principal");
    };
    let (desc, op_id, state) = match request_live_daemon_stop(&root, site_id.as_deref(), principal)
    {
        Ok(v) => v,
        Err(err) => return fail_json(json, err.error_id(), &err.to_string()),
    };
    if json {
        println!("{}", render_stop_accepted_json(&desc, &op_id, state));
    } else {
        println!(
            "fss-daemon stop accepted site={} operation_id={} state={state:?}",
            desc.site_id,
            op_id.as_str()
        );
    }
    ExitCode::SUCCESS
}

fn parse_root_and_site(args: &[String]) -> Result<(PathBuf, Option<String>, bool), ExitCode> {
    let mut root: Option<PathBuf> = None;
    let mut site_id: Option<String> = None;
    let mut json = false;
    let mut idx = 0_usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--root" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return Err(fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "missing --root value",
                    ));
                };
                root = Some(PathBuf::from(val));
            }
            "--site-id" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return Err(fail_json(
                        json,
                        "ERR-DAEMON-MANIFEST-INVALID-001",
                        "missing --site-id value",
                    ));
                };
                site_id = Some(val.clone());
            }
            "--json" => json = true,
            other => {
                return Err(fail_json(
                    json,
                    "ERR-DAEMON-MANIFEST-INVALID-001",
                    &format!("unknown option `{other}`"),
                ));
            }
        }
        idx += 1;
    }
    let Some(root) = root else {
        return Err(fail_json(
            json,
            "ERR-DAEMON-MANIFEST-INVALID-001",
            "--root is required",
        ));
    };
    Ok((root, site_id, json))
}

fn fail_json(json: bool, error_id: &str, message: &str) -> ExitCode {
    if json {
        println!(
            "{{\"schema\":\"fss.daemon_error.v1\",\"error_id\":\"{}\",\"reason\":\"{}\"}}",
            escape_json(error_id),
            escape_json(message),
        );
    } else {
        eprintln!("{error_id}: {message}");
    }
    ExitCode::from(1)
}

const fn help_text() -> &'static str {
    "fss-daemon — Always-on Asupersync-owned multi-camera supervisor\n\nUSAGE:\n  fss-daemon run --manifest <site.json> [--root <deploy>] [--once-ticks <N>] [--tick-ms <N>] [--sensor-health conservative-v1] [--json]\n  fss-daemon status --root <deploy> [--site-id <id>] [--json]\n  fss-daemon retention-forecast <camera-id> --root <deploy> [--site-id <id>] [--json]\n  fss-daemon stop --root <deploy> [--site-id <id>] [--json]\n  fss-daemon version\n  fss-daemon help"
}
