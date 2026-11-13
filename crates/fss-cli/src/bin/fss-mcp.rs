#![forbid(unsafe_code)]
//! Owner-launched MCP stdio transport for native FSS reads and agent-session continuity.
//! This is a bounded synchronous reference adapter, not a production network service.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "fss_mcp/control.rs"]
mod control;
#[path = "fss_mcp/coordination.rs"]
mod coordination;
#[path = "fss_mcp/event_hydration.rs"]
mod event_hydration;
#[path = "fss_mcp/feedback.rs"]
mod feedback;
#[path = "fss_mcp/investigate.rs"]
mod investigate;
#[path = "fss_mcp/json.rs"]
mod json;
#[path = "fss_mcp/onvif.rs"]
mod onvif;
#[path = "fss_mcp/qsr.rs"]
mod qsr;
#[path = "fss_mcp/recordings.rs"]
mod recordings;
#[path = "fss_mcp/report_catalog.rs"]
mod report_catalog;
#[path = "fss_mcp/server.rs"]
mod server;
#[path = "fss_mcp/tracks.rs"]
mod tracks;

const HELP: &str = "fss-mcp --root EXISTING_DEPLOYMENT [--principal PRINCIPAL_ID] [--archive-root EXISTING_ARCHIVE]\n\
        [--allow-replay-source-verification] [--allow-qsr-source-verification]\n\
        [--allow-tracks-source-verification]\n\
MCP 2025-06-18 over newline-delimited JSON-RPC on stdin/stdout.\n\
The operator fixes root, optional archive root and principal; clients cannot override them.\n\
Catalog queries and archive recorder replay require the optional archive binding.\n\
Explicit retained-import recorder queries use the fixed deployment without an archive.\n\
Recorder UTC replay requires the launcher's explicit source-verification grant in either mode;\n\
clients cannot enable it. The grant permits bounded verification in the fixed source owner,\n\
with exact replay pins and no source disclosure, pixel decode, network or publication.\n\
QSR reads require the separate QSR source-verification grant and an exact retained report.\n\
They verify original encoded evidence without returning media or creating retained state.\n\
Detector track reads require the separate tracks source-verification grant and exact report.\n\
They return matched observations with tentative/confirmed state and continuity boundaries.\n\
Report discovery returns retained metadata handles without a source-verification grant.\n\
Event evidence-hydration uses an existing session and exact current event revision/anchor.\n\
H0 costs 5000 and H1 costs 16000 cumulative tokens; agent-journal charge/cursor writes\n\
precede output. Use the full receipt.continuation JSON for H1; consumed cursors never replay.\n\
No source-media grant is needed or admitted; H2/H3/H4 are unavailable.\n\
The principal is an audit label, not authentication. Session open/handoff/resume and explicit\n\
durable follow, investigate and advisory feedback write agent state. Alert controls\n\
use native exact approvals and durable receipts; inspect with wait after response loss.\n\
No network listener. Follow/wait reads are at most 10 seconds; source verification\n\
event hydration and approved dispatch are at most 60 seconds (cooperative).\n\
Mission text is literal, never a file to read. Session budgets are cumulative;\n\
same-head retry and resume behavior comes from the native session implementation.\n\
Input frames are limited to 64 KiB; semantic responses to 4 MiB before escaping.\n\
Diagnostics go only to stderr. EOF shuts down. Reference-only, not qualified.\n";

#[derive(Debug, Eq, PartialEq)]
struct Options {
    root: OsString,
    principal: String,
    archive_root: Option<OsString>,
    allow_replay_source_verification: bool,
    allow_qsr_source_verification: bool,
    allow_tracks_source_verification: bool,
}

fn options(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>, &'static str> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Err("--root is required");
    };
    if first == "--help" || first == "-h" {
        return if args.next().is_none() {
            Ok(None)
        } else {
            Err("unexpected help argument")
        };
    }
    let mut root = None;
    let mut principal = None;
    let mut archive_root = None;
    let mut allow_replay_source_verification = false;
    let mut allow_qsr_source_verification = false;
    let mut allow_tracks_source_verification = false;
    let mut flag = Some(first);
    while let Some(current) = flag {
        if current == "--allow-replay-source-verification" {
            if allow_replay_source_verification {
                return Err("duplicate replay source-verification grant");
            }
            allow_replay_source_verification = true;
            flag = args.next();
            continue;
        }
        if current == "--allow-qsr-source-verification" {
            if allow_qsr_source_verification {
                return Err("duplicate QSR source-verification grant");
            }
            allow_qsr_source_verification = true;
            flag = args.next();
            continue;
        }
        if current == "--allow-tracks-source-verification" {
            if allow_tracks_source_verification {
                return Err("duplicate tracks source-verification grant");
            }
            allow_tracks_source_verification = true;
            flag = args.next();
            continue;
        }
        if current != "--root" && current != "--principal" && current != "--archive-root" {
            return Err("unknown option");
        }
        let value = args.next().ok_or("missing option value")?;
        if current == "--root" {
            if root.replace(value).is_some() {
                return Err("duplicate root");
            }
        } else if current == "--archive-root" {
            if value.is_empty() || archive_root.replace(value).is_some() {
                return Err("empty or duplicate archive root");
            }
        } else if principal.replace(value).is_some() {
            return Err("duplicate principal");
        }
        flag = args.next();
    }
    let root = root.ok_or("--root is required")?;
    let principal = principal.map_or_else(
        || Ok(fss_cli::orient_cmd::DEFAULT_PRINCIPAL.to_owned()),
        |value| value.into_string().map_err(|_| "principal must be UTF-8"),
    )?;
    // Use the real CLI parser to validate the fixed principal and path without executing a read.
    fss_cli::parse_fss_args([
        OsString::from("orient"),
        "--json".into(),
        "--root".into(),
        root.clone(),
        format!("--principal={principal}").into(),
    ])
    .map_err(|_| "invalid root or principal")?;
    Ok(Some(Options {
        root,
        principal,
        archive_root,
        allow_replay_source_verification,
        allow_qsr_source_verification,
        allow_tracks_source_verification,
    }))
}

fn main() -> ExitCode {
    let Options {
        root,
        principal,
        archive_root,
        allow_replay_source_verification,
        allow_qsr_source_verification,
        allow_tracks_source_verification,
    } = match options(std::env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            eprint!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("fss-mcp: {message}");
            return ExitCode::from(2);
        }
    };
    let root = match PathBuf::from(root).canonicalize() {
        Ok(path) if path.is_dir() => path,
        _ => {
            eprintln!("fss-mcp: root must be an accessible existing directory");
            return ExitCode::from(2);
        }
    };
    let mut server = server::Server::new(root.into_os_string(), principal);
    if let Some(archive_root) = archive_root {
        let archive_root = match PathBuf::from(archive_root).canonicalize() {
            Ok(path) if path.is_dir() => path,
            _ => {
                eprintln!("fss-mcp: archive root must be an accessible existing directory");
                return ExitCode::from(2);
            }
        };
        server = server.with_archive(archive_root.into_os_string());
    }
    if allow_replay_source_verification {
        server = server.with_replay_source_verification();
    }
    if allow_qsr_source_verification {
        server = server.with_qsr_source_verification();
    }
    if allow_tracks_source_verification {
        server = server.with_tracks_source_verification();
    }
    match server::serve(&mut server, io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("fss-mcp: transport stopped after an I/O or framing failure");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_scope_is_explicit_and_options_are_total() {
        for args in [
            vec![],
            vec!["--root"],
            vec!["--root", "/x", "--root", "/y"],
            vec!["--root", "/x", "--listen", "0.0.0.0"],
            vec!["--help", "extra"],
            vec!["--root", "/x", "--principal", "invalid principal"],
            vec!["--root", "/x", "--archive-root"],
            vec!["--root", "/x", "--archive-root", ""],
            vec![
                "--root",
                "/x",
                "--archive-root",
                "/a",
                "--archive-root",
                "/b",
            ],
        ] {
            assert!(options(args.into_iter().map(OsString::from)).is_err());
        }
        assert!(options([OsString::from("--help")]).is_ok_and(|value| value.is_none()));
        assert!(
            options(["--root", "/owner/deployment"].map(OsString::from))
                .is_ok_and(|value| value.is_some())
        );
    }

    #[test]
    fn archive_binding_is_explicit_and_preserves_owner_paths() {
        let parsed = options(
            [
                "--archive-root",
                "/owner/archive with spaces",
                "--root",
                "/owner/deployment",
                "--principal",
                "principal:archive-operator",
            ]
            .map(OsString::from),
        );
        assert_eq!(
            parsed,
            Ok(Some(Options {
                root: "/owner/deployment".into(),
                principal: "principal:archive-operator".into(),
                archive_root: Some("/owner/archive with spaces".into()),
                allow_replay_source_verification: false,
                allow_qsr_source_verification: false,
                allow_tracks_source_verification: false,
            }))
        );
        assert!(
            options(["--root", "/owner/deployment"].map(OsString::from))
                .is_ok_and(|value| value.is_some_and(|value| value.archive_root.is_none()))
        );
    }

    #[test]
    fn replay_source_verification_is_an_explicit_launcher_only_grant() -> Result<(), &'static str> {
        let parsed = options(
            [
                "--root",
                "/owner/deployment",
                "--archive-root",
                "/owner/archive",
                "--allow-replay-source-verification",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing launcher options")?;
        assert!(parsed.allow_replay_source_verification);
        let retained = options(
            [
                "--root",
                "/owner/deployment with spaces",
                "--allow-replay-source-verification",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing retained-source launcher options")?;
        assert!(retained.allow_replay_source_verification);
        assert!(retained.archive_root.is_none());
        assert_eq!(
            retained.root,
            OsString::from("/owner/deployment with spaces")
        );
        for args in [
            vec![
                "--root",
                "/owner/deployment",
                "--archive-root",
                "/owner/archive",
                "--allow-replay-source-verification",
                "--allow-replay-source-verification",
            ],
            vec![
                "--root",
                "/owner/deployment",
                "--archive-root",
                "/owner/archive",
                "--allow-replay-source-verification=yes",
            ],
        ] {
            assert!(options(args.into_iter().map(OsString::from)).is_err());
        }
        let ordinary = options(
            [
                "--root",
                "/owner/deployment",
                "--archive-root",
                "/owner/archive",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing ordinary options")?;
        assert!(!ordinary.allow_replay_source_verification);
        assert!(!ordinary.allow_qsr_source_verification);
        assert!(!ordinary.allow_tracks_source_verification);
        Ok(())
    }

    #[test]
    fn tracks_grant_is_separate_and_cannot_be_renewed_by_client_flags() -> Result<(), &'static str>
    {
        let tracks = options(
            [
                "--root",
                "/owner/deployment",
                "--allow-tracks-source-verification",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing tracks launcher options")?;
        assert!(tracks.allow_tracks_source_verification);
        assert!(!tracks.allow_qsr_source_verification);
        assert!(!tracks.allow_replay_source_verification);
        for flags in [
            vec![
                "--allow-tracks-source-verification",
                "--allow-tracks-source-verification",
            ],
            vec!["--allow-tracks-source-verification=yes"],
            vec!["--verify-tracks-source=yes"],
        ] {
            assert!(
                options(
                    ["--root", "/owner/deployment"]
                        .into_iter()
                        .chain(flags)
                        .map(OsString::from)
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn qsr_source_verification_is_a_separate_launcher_grant() -> Result<(), &'static str> {
        let qsr = options(
            [
                "--allow-qsr-source-verification",
                "--root",
                "/owner/deployment with spaces",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing QSR launcher options")?;
        assert!(qsr.allow_qsr_source_verification);
        assert!(!qsr.allow_replay_source_verification);
        assert!(!qsr.allow_tracks_source_verification);
        assert!(qsr.archive_root.is_none());
        let replay = options(
            [
                "--root",
                "/owner/deployment",
                "--allow-replay-source-verification",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing recorder options")?;
        assert!(!replay.allow_qsr_source_verification);
        assert!(!replay.allow_tracks_source_verification);
        let both = options(
            [
                "--root",
                "/owner/deployment",
                "--allow-replay-source-verification",
                "--allow-qsr-source-verification",
            ]
            .map(OsString::from),
        )?
        .ok_or("missing combined options")?;
        assert!(both.allow_qsr_source_verification && both.allow_replay_source_verification);
        assert!(!both.allow_tracks_source_verification);
        for args in [
            vec![
                "--root",
                "/owner/deployment",
                "--allow-qsr-source-verification",
                "--allow-qsr-source-verification",
            ],
            vec![
                "--root",
                "/owner/deployment",
                "--allow-qsr-source-verification=yes",
            ],
            vec!["--root", "/owner/deployment", "--verify-qsr-source=yes"],
        ] {
            assert!(options(args.into_iter().map(OsString::from)).is_err());
        }
        Ok(())
    }
}
