#![forbid(unsafe_code)]
//! Owner-launched, read-only MCP stdio transport for existing FSS agent reads.
//! This is a bounded synchronous reference adapter, not a production network service.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "fss_mcp/json.rs"]
mod json;
#[path = "fss_mcp/server.rs"]
mod server;

const HELP: &str = "fss-mcp --root EXISTING_DEPLOYMENT [--principal PRINCIPAL_ID]\n\
Read-only MCP 2025-06-18 over newline-delimited JSON-RPC on stdin/stdout.\n\
The operator fixes root and principal; clients cannot override them. The principal\n\
is an audit label, not authentication. No network listener or write tools.\n\
Input frames are limited to 64 KiB; semantic responses to 4 MiB before escaping.\n\
Diagnostics go only to stderr. EOF shuts down. Reference-only, not qualified.\n";

fn options(args: impl IntoIterator<Item = OsString>) -> Result<Option<(OsString, String)>, &'static str> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else { return Err("--root is required"); };
    if first == "--help" || first == "-h" {
        return if args.next().is_none() { Ok(None) } else { Err("unexpected help argument") };
    }
    let mut root = None;
    let mut principal = None;
    let mut flag = Some(first);
    while let Some(current) = flag {
        if current != "--root" && current != "--principal" { return Err("unknown option"); }
        let value = args.next().ok_or("missing option value")?;
        if current == "--root" {
            if root.replace(value).is_some() { return Err("duplicate root"); }
        } else if principal.replace(value).is_some() { return Err("duplicate principal"); }
        flag = args.next();
    }
    let root = root.ok_or("--root is required")?;
    let principal = principal.map_or_else(
        || Ok(fss_cli::orient_cmd::DEFAULT_PRINCIPAL.to_owned()),
        |value| value.into_string().map_err(|_| "principal must be UTF-8"),
    )?;
    // Use the real CLI parser to validate the fixed principal and path without executing a read.
    fss_cli::parse_fss_args([
        OsString::from("orient"), "--json".into(), "--root".into(), root.clone(),
        format!("--principal={principal}").into(),
    ]).map_err(|_| "invalid root or principal")?;
    Ok(Some((root, principal)))
}

fn main() -> ExitCode {
    let (root, principal) = match options(std::env::args_os().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => { eprint!("{HELP}"); return ExitCode::SUCCESS; }
        Err(message) => { eprintln!("fss-mcp: {message}"); return ExitCode::from(2); }
    };
    let root = match PathBuf::from(root).canonicalize() {
        Ok(path) if path.is_dir() => path,
        _ => { eprintln!("fss-mcp: root must be an accessible existing directory"); return ExitCode::from(2); }
    };
    let mut server = server::Server::new(root.into_os_string(), principal);
    match server::serve(&mut server, io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(_) => { eprintln!("fss-mcp: transport stopped after an I/O or framing failure"); ExitCode::from(1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_scope_is_explicit_and_options_are_total() {
        for args in [vec![], vec!["--root"], vec!["--root", "/x", "--root", "/y"],
            vec!["--root", "/x", "--listen", "0.0.0.0"], vec!["--help", "extra"],
            vec!["--root", "/x", "--principal", "invalid principal"]] {
            assert!(options(args.into_iter().map(OsString::from)).is_err());
        }
        assert!(options([OsString::from("--help")]).is_ok_and(|value| value.is_none()));
        assert!(options(["--root", "/owner/deployment"].map(OsString::from)).is_ok_and(|value| value.is_some()));
    }
}
