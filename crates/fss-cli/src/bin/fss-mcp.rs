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
#[path = "fss_mcp/feedback.rs"]
mod feedback;
#[path = "fss_mcp/investigate.rs"]
mod investigate;
#[path = "fss_mcp/json.rs"]
mod json;
#[path = "fss_mcp/recordings.rs"]
mod recordings;
#[path = "fss_mcp/server.rs"]
mod server;

const HELP: &str = "fss-mcp --root EXISTING_DEPLOYMENT [--principal PRINCIPAL_ID] [--archive-root EXISTING_ARCHIVE]\n\
MCP 2025-06-18 over newline-delimited JSON-RPC on stdin/stdout.\n\
The operator fixes root, optional archive root and principal; clients cannot override them.\n\
Native recording queries require an archive binding and return metadata, never media bytes.\n\
The principal is an audit label, not authentication. Session open/handoff/resume and explicit\n\
durable follow, investigate and advisory feedback write agent state. Alert controls\n\
use native exact approvals and durable receipts; inspect with wait after response loss.\n\
No network listener. Read waits are at most 10 seconds; approved dispatch at most 60.\n\
Mission text is literal, never a file to read. Session budgets are cumulative;\n\
same-head retry and resume behavior comes from the native session implementation.\n\
Input frames are limited to 64 KiB; semantic responses to 4 MiB before escaping.\n\
Diagnostics go only to stderr. EOF shuts down. Reference-only, not qualified.\n";

#[derive(Debug, Eq, PartialEq)]
struct Options {
    root: OsString,
    principal: String,
    archive_root: Option<OsString>,
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
    let mut flag = Some(first);
    while let Some(current) = flag {
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
    }))
}

fn main() -> ExitCode {
    let Options {
        root,
        principal,
        archive_root,
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
            vec!["--root", "/x", "--archive-root", "/a", "--archive-root", "/b"],
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
            }))
        );
        assert!(
            options(["--root", "/owner/deployment"].map(OsString::from))
                .is_ok_and(|value| value.is_some_and(|value| value.archive_root.is_none()))
        );
    }
}
