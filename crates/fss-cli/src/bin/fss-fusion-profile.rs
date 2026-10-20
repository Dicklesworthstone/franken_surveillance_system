#![forbid(unsafe_code)]
//! Bounded, offline profile authoring from explicit scope pins and labelled counts on stdin.
//! Produces inert control input only; never opens a deployment, model, source file or network.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use fss_cli::agent_json::{object, string};
use fss_cli::event_fusion::{EventFusionError, EventFusionProfile, MAX_PROFILE_BYTES};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, PrincipalId,
    RootAuthoritySpec,
};

const MAX_ARGUMENTS: usize = 14;
const MAX_OUTPUT_BYTES: usize = MAX_PROFILE_BYTES + 4096;
const INTERRUPT_LIMIT: u8 = 8;
const HELP: &str = "fss-fusion-profile --scope watch|dwell|corroborate \\\n  --counts-digest sha256:HEX --analysis-digest sha256:HEX \\\n  --detector-recipe-digest sha256:HEX --analysis-roots sha256:HEX[,sha256:HEX] \\\n  [--format profile|report] [--principal principal:ID] < counts.json\n\n\
Reads at most 256 KiB of labelled-count JSON from stdin, verifies its exact digest BEFORE\n\
parsing, and rebuilds calibration through the native count-calibration owner. Every prior,\n\
policy, consequence, look count and evidence-clock value must be explicit in the counts.\n\
Scope pins are owner-selected metadata: watch or dwell needs one complete analysis root;\n\
corroborate needs two distinct roots in native camera order. No coverage is invented.\n\
Default format profile emits the exact reusable profile plus one newline. Format report\n\
embeds that profile and reports its semantic digest and the SHA-256 of those exact file\n\
bytes (INCLUDING the newline), suitable for --fusion-digest. Repeat with format profile\n\
and unchanged inputs to produce the named bytes. Watch uses v2, corroboration v3, dwell v4.\n\
No source/model/credential files, deployment, camera, wall clock or network are accessed.\n\
No event, calibration, coverage, retention or alert policy is activated or published.\n\
The principal is an audit label, not camera authentication. Profile authoring does not\n\
verify source custody or deployment applicability; the native analysis consumer does.\n";

type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug)]
enum Failure {
    Argument,
    Authority,
    Input,
    Output,
    Fusion(EventFusionError),
}
impl Failure {
    fn code(&self) -> &'static str {
        match self {
            Self::Argument => ERR_CLI_MALFORMED_VALUE,
            Self::Fusion(error) => error.stable_id(),
            Self::Authority | Self::Input | Self::Output => ERR_CLI_RUNTIME_FAILURE,
        }
    }
}
impl From<EventFusionError> for Failure {
    fn from(error: EventFusionError) -> Self {
        Self::Fusion(error)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scope {
    Watch,
    Dwell,
    Corroboration,
}

struct Options {
    scope: Scope,
    counts: ContentDigest,
    analysis: ContentDigest,
    recipe: ContentDigest,
    roots: Vec<ContentDigest>,
    report: bool,
    principal: PrincipalId,
}
fn digest(text: &str) -> Result<ContentDigest> {
    ContentDigest::parse(text)
        .ok()
        .filter(|value| value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32])
        .ok_or(Failure::Argument)
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self> {
        if args.len() > MAX_ARGUMENTS || !args.len().is_multiple_of(2) {
            return Err(Failure::Argument);
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(Failure::Argument)?;
            let value = pair[1].to_str().ok_or(Failure::Argument)?;
            if key.len() > 64
                || value.is_empty()
                || value.len() > 512
                || values.insert(key, value).is_some()
            {
                return Err(Failure::Argument);
            }
        }
        let scope = match values.remove("--scope") {
            Some("watch") => Scope::Watch,
            Some("dwell") => Scope::Dwell,
            Some("corroborate") => Scope::Corroboration,
            _ => return Err(Failure::Argument),
        };
        let counts = digest(values.remove("--counts-digest").ok_or(Failure::Argument)?)?;
        let analysis = digest(
            values
                .remove("--analysis-digest")
                .ok_or(Failure::Argument)?,
        )?;
        let recipe = digest(
            values
                .remove("--detector-recipe-digest")
                .ok_or(Failure::Argument)?,
        )?;
        let roots: Vec<_> = values
            .remove("--analysis-roots")
            .ok_or(Failure::Argument)?
            .split(',')
            .map(digest)
            .collect::<Result<_>>()?;
        let paired = scope == Scope::Corroboration;
        if roots.len() != if paired { 2 } else { 1 } || (paired && roots[0] == roots[1]) {
            return Err(Failure::Argument);
        }
        let report = match values.remove("--format") {
            None | Some("profile") => false,
            Some("report") => true,
            _ => return Err(Failure::Argument),
        };
        let principal = PrincipalId::parse(
            values
                .remove("--principal")
                .unwrap_or("principal:local-operator"),
        )
        .map_err(|_| Failure::Argument)?;
        if !values.is_empty() {
            return Err(Failure::Argument);
        }
        Ok(Self {
            scope,
            counts,
            analysis,
            recipe,
            roots,
            report,
            principal,
        })
    }

    fn render(&self, bytes: &[u8]) -> Result<String> {
        let profile = match self.scope {
            Scope::Corroboration => EventFusionProfile::from_long_corroboration_counts_json(
                bytes,
                self.counts,
                self.analysis,
                self.recipe,
                [self.roots[0], self.roots[1]],
            )?,
            Scope::Watch => EventFusionProfile::from_long_watch_counts_json(
                bytes,
                self.counts,
                self.analysis,
                self.recipe,
                self.roots[0],
            )?,
            Scope::Dwell => EventFusionProfile::from_long_dwell_counts_json(
                bytes,
                self.counts,
                self.analysis,
                self.recipe,
                self.roots[0],
            )?,
        };
        let json = profile.to_json()?;
        let file_bytes = format!("{json}\n");
        let output = if self.report {
            object(&[
                ("schema", string("fss.fusion_profile_authoring.v1")),
                ("profile", json),
                ("profile_digest", string(&profile.digest().to_text())),
                (
                    "profile_file_digest",
                    string(&ContentDigest::sha256(file_bytes.as_bytes()).to_text()),
                ),
                ("profile_file_bytes", file_bytes.len().to_string()),
                ("file_ending", string("one_lf")),
                ("counts_digest", string(&self.counts.to_text())),
                ("source_scope_verified", "false".into()),
                (
                    "calibration_applicability",
                    string("owner_asserted_not_deployment_qualification"),
                ),
                ("published", "false".into()),
                ("effect_authority", "false".into()),
            ]) + "\n"
        } else {
            file_bytes
        };
        if output.len() > MAX_OUTPUT_BYTES {
            return Err(EventFusionError::Limit.into());
        }
        Ok(output)
    }
}

/// Explicit local owner of only the bounded stdin/stdout exchange. Empty capabilities
/// grant neither replay/deployment access nor effects; the scope pins are inert inputs.
struct StdioOwner(ContextAuthority);
impl StdioOwner {
    fn new(principal: &str, input: ContentDigest) -> Result<Self> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:fusion-profile".into(),
            operation_id: OperationId::parse("operation:fusion-profile")
                .map_err(|_| Failure::Authority)?,
            principal: principal.to_owned(),
            capabilities: Vec::new(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes((MAX_PROFILE_BYTES + MAX_OUTPUT_BYTES + 1) as u64)
                .build()
                .map_err(|_| Failure::Authority)?,
            privacy_scope: "privacy:operator-supplied-counts".into(),
            retention_scope: "retention:stdout-control-document-only".into(),
            anchor_universe: input,
            generation: 1,
        })
        .map_err(|_| Failure::Authority)?;
        Ok(Self(authority))
    }
    fn checkpoint(&self) -> Result<()> {
        self.0.validate().map_err(|_| Failure::Authority)?;
        if self.0.cancellation_reason.is_some() {
            return Err(EventFusionError::Cancelled.into());
        }
        Ok(())
    }
}

fn read_counts(input: &mut impl Read, owner: &StdioOwner) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut block = [0_u8; 8192];
    let mut interrupted = 0_u8;
    loop {
        owner.checkpoint()?;
        let size = block.len().min(MAX_PROFILE_BYTES + 1 - bytes.len());
        match input.read(&mut block[..size]) {
            Ok(0) => break,
            Ok(count) if count <= size => {
                bytes.extend_from_slice(&block[..count]);
                interrupted = 0;
                if bytes.len() > MAX_PROFILE_BYTES {
                    return Err(EventFusionError::Limit.into());
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    && interrupted + 1 < INTERRUPT_LIMIT =>
            {
                interrupted += 1;
            }
            Ok(_) | Err(_) => return Err(Failure::Input),
        }
    }
    owner.checkpoint()?;
    Ok(bytes)
}

fn write_output(out: &mut impl Write, bytes: &[u8], owner: &StdioOwner) -> Result<()> {
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(EventFusionError::Limit.into());
    }
    let mut offset = 0;
    let mut interrupted = 0_u8;
    while offset < bytes.len() {
        owner.checkpoint()?;
        let end = (offset + 8192).min(bytes.len());
        match out.write(&bytes[offset..end]) {
            Ok(0) => return Err(Failure::Output),
            Ok(count) if count <= end - offset => {
                offset += count;
                interrupted = 0;
            }
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    && interrupted + 1 < INTERRUPT_LIMIT =>
            {
                interrupted += 1;
            }
            Ok(_) | Err(_) => return Err(Failure::Output),
        }
    }
    for _ in 0..INTERRUPT_LIMIT {
        owner.checkpoint()?;
        match out.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Failure::Output),
        }
    }
    Err(Failure::Output)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .take(MAX_ARGUMENTS + 1)
        .collect();
    let result = (|| {
        // Even fixed help uses the same bounded, explicitly owned output path.
        if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
            let owner = StdioOwner::new(
                "principal:local-operator",
                ContentDigest::sha256(HELP.as_bytes()),
            )?;
            return write_output(&mut io::stdout().lock(), HELP.as_bytes(), &owner);
        }
        let options = Options::parse(&args)?;
        let owner = StdioOwner::new(options.principal.as_str(), options.counts)?;
        let bytes = read_counts(&mut io::stdin().lock(), &owner)?;
        owner.checkpoint()?;
        let output = options.render(&bytes)?;
        write_output(&mut io::stdout().lock(), output.as_bytes(), &owner)
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}: profile authoring refused; use --help", error.code());
            ExitCode::from(if matches!(error, Failure::Argument) {
                ExitIdentity::MALFORMED_VALUE.code
            } else {
                ExitIdentity::RUNTIME_FAILURE.code
            })
        }
    }
}
