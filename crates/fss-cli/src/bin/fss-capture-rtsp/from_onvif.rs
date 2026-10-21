#![forbid(unsafe_code)]
//! Protected ONVIF metadata becomes an ordinary, separately approved capture plan.
//! The file provides only the exact route and codec, never source/timing authority.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId};

use super::driver;
use super::plan::Options;
use super::reconnect::{self, ReconnectPlan};

#[path = "../fss-onvif/handoff.rs"]
mod handoff;
#[path = "../fss-onvif/private_file.rs"]
mod private_file;
#[path = "../fss-onvif/runtime.rs"]
mod runtime;

const ERROR: &str = "ERR-CAPTURE-ONVIF-HANDOFF-001";
const POLICY: &str = "private-digest-bound-stable-onvif-uri:separate-owner-capture-approval:\
unchanged-source-clock-timing-and-independent-pin-owners:no-camera-or-credential-read-in-preview:v1";
const RECONNECT_POLICY: &str = "private-digest-bound-stable-onvif-uri:explicit-native-reconnect-owner:\
separate-owner-approval:all-derived-destinations-disjoint:private-child-previews:\
fresh-observed-recovery-approval:no-camera-or-credential-read-in-preview:v2";
pub(super) const MAX_ARGUMENTS: usize = reconnect::MAX_ARGUMENTS + 6;

pub(super) const HELP: &str = "fss-capture-rtsp from-onvif\n\
  --onvif-source /PRIVATE_HANDOFF --onvif-digest sha256:HEX\n\
  --control-root /OWNER_APPROVED_TRACK_SUBTREE [ordinary capture source/timing/store options]\n\
  [--capture-mode single|reconnect] [existing reconnect/source/recovery options]\n\
  [--approve sha256:HEX]\n\
\n\
This mode reads only the exact private handoff produced by approved `fss-onvif --profile ...`.\n\
Supply its output_digest from the safe result. Preview reads bounded protected metadata through\n\
an owned context, opens no camera or credentials, and emits a new capture approval. Repeat all\n\
options with that approval. File content, identity, permissions and digest are checked again\n\
before entering the existing native capture owner. No source/timing identity is inferred.\n\
\n\
The handoff supplies peer, authority, exact presentation URI and AVC or HEVC codec. Do not supply\n\
--peer, --authority, --presentation or --codec. The owner must supply --control-root plus\n\
all ordinary required sensor/stream/generation/ingress/SSRC, source and clock digests, cadence,\n\
new archive and independent pin-journal paths, budgets and original-retention authorization.\n\
Queries and safe percent escapes are preserved exactly and redacted from stdout. The control\n\
root remains an explicit query-free subtree; camera metadata cannot authorize sibling tracks.\n\
RTSP Digest, if needed, requires its own --credential-file and exact --auth-realm options.\n\
\n\
Stable Media1 H.264 and Media2 H.264/H.265 handoffs are accepted. Inventory files, unsupported codecs, expiring\n\
URIs, embedded credentials, altered files, symlinks and nonprivate permissions refuse.\n\
The handoff grants no recording, source custody, clock, identity or conformance authority.\n\
The default --capture-mode single preserves one ordinary capture attempt and its exact paths.\n\
--capture-mode reconnect delegates the existing finite reconnect/campaign owner: all its\n\
watchdog, duration, retry, --continue-after-success and --source-root options remain explicit.\n\
Use --max-attempts 1 for one supervised session. Archive, pin and source prefixes derive\n\
independent PREFIX.attempt-0001 destinations; every destination is checked against the handoff.\n\
See `fss-capture-rtsp reconnect --help` for limits and retention/retry consequences.\n\
\n\
Offline recovery repeats the ORIGINAL reconnect-mode options plus --recover yes or index.\n\
Remove the capture approval and preview again, then approve the NEW OUTER handoff plan.\n\
It binds the fresh native recovery/index observations as well as the protected handoff.\n\
Neither a capture approval nor the nested native approval can authorize this wrapper.\n\
Recovery opens no camera or credentials; source/index inspection may read retained evidence.\n\
Native recovery revalidates its exact observed stores before writing. Preserve all stores\n\
on failure, preview again and approve current state. Recovery never resumes camera capture.\n";

#[derive(Clone, Copy, Eq, PartialEq)]
enum CaptureMode {
    Single,
    Reconnect,
}

impl CaptureMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Reconnect => "reconnect",
        }
    }
}

enum NativeCapture {
    Single(Box<Options>),
    Reconnect(Box<ReconnectPlan>),
}

impl NativeCapture {
    fn parse(mode: CaptureMode, args: &[OsString]) -> Result<Self, &'static str> {
        match mode {
            CaptureMode::Single => Options::parse(args).map(|plan| Self::Single(Box::new(plan))),
            CaptureMode::Reconnect => {
                ReconnectPlan::parse(args).map(|plan| Self::Reconnect(Box::new(plan)))
            }
        }
    }

    fn paths(&self) -> Result<Vec<&Path>, &'static str> {
        match self {
            Self::Single(plan) => Ok(vec![plan.root.as_path(), plan.pins.as_path()]),
            Self::Reconnect(plan) => plan.output_paths(),
        }
    }

    fn prepared_preview(&self) -> Result<(ContentDigest, String), &'static str> {
        match self {
            Self::Single(plan) => Ok((plan.digest()?, plan.private_uri_preview()?)),
            Self::Reconnect(plan) => plan.private_prepared_preview(),
        }
    }

    fn operation_kind(&self) -> &'static str {
        match self {
            Self::Single(_) => "capture",
            Self::Reconnect(plan) => plan.operation_kind(),
        }
    }

    fn execute(
        self,
        validate_approval: &impl Fn(ContentDigest) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Single(mut plan) => {
                let approval = plan.digest()?;
                validate_approval(approval)?;
                plan.approve = Some(approval);
                driver::execute(&plan)
            }
            Self::Reconnect(mut plan) => plan.execute_validated(validate_approval),
        }
    }
}

pub(super) struct SourcePlan {
    source: PathBuf,
    expected: ContentDigest,
    approval: Option<ContentDigest>,
    principal: String,
    mode: CaptureMode,
    capture_args: Vec<OsString>,
}

struct Prepared {
    capture: NativeCapture,
    identity: ContentDigest,
}

impl SourcePlan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ERROR);
        }
        let mut source = None;
        let mut expected = None;
        let mut approval = None;
        let mut principal = "principal:local-operator".to_owned();
        let mut mode = CaptureMode::Single;
        let mut capture_args = Vec::new();
        let mut seen = BTreeSet::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ERROR)?;
            let value = pair[1].to_str().ok_or(ERROR)?;
            if value.is_empty() || !seen.insert(key) {
                return Err(ERROR);
            }
            match key {
                "--onvif-source" => source = Some(private_file::absolute_path(value)?),
                "--onvif-digest" => expected = Some(handoff::digest(value)?),
                "--approve" => approval = Some(handoff::digest(value)?),
                "--capture-mode" => {
                    mode = match value {
                        "single" => CaptureMode::Single,
                        "reconnect" => CaptureMode::Reconnect,
                        _ => return Err(ERROR),
                    };
                }
                "--peer" | "--authority" | "--presentation" | "--codec" => return Err(ERROR),
                _ => {
                    if key == "--principal" {
                        principal = value.to_owned();
                    }
                    capture_args.extend_from_slice(pair);
                }
            }
        }
        PrincipalId::parse(&principal).map_err(|_| ERROR)?;
        if principal.len() > 256 {
            return Err(ERROR);
        }
        Ok(Self {
            source: source.ok_or(ERROR)?,
            expected: expected.ok_or(ERROR)?,
            approval,
            principal,
            mode,
            capture_args,
        })
    }

    pub(super) fn approved(&self) -> bool {
        self.approval.is_some()
    }

    fn read(&self) -> Result<Prepared, &'static str> {
        let request = runtime::Request {
            approval: self.expected,
            principal: self.principal.clone(),
            timeout_ns: 5_000_000_000,
            bytes: private_file::MAX_FILE_BYTES as u64 + 8192,
            network_bytes: 0,
            storage_operations: 8192,
            network: false,
            write: false,
            secrets: false,
        };
        runtime::run(request, |scope| {
            let input = private_file::InputLease::open(&self.source, &|| scope.input())?;
            if ContentDigest::sha256(input.bytes()) != self.expected {
                return Err(ERROR);
            }
            let handoff = handoff::Handoff::parse(input.bytes())?;
            let mut args = self.capture_args.clone();
            for (key, value) in [
                ("--peer", handoff.peer.to_string()),
                ("--authority", handoff.authority.clone()),
                ("--presentation", handoff.presentation()?.to_owned()),
                ("--codec", handoff.codec.clone()),
            ] {
                args.push(OsString::from(key));
                args.push(OsString::from(value));
            }
            let capture = NativeCapture::parse(self.mode, &args)?;
            for output in capture.paths()? {
                self.check_destination(output, &|| scope.input())?;
            }
            input.revalidate(&|| scope.input())?;
            Ok(Prepared {
                capture,
                identity: ContentDigest::sha256(&input.fingerprint()),
            })
        })
    }

    fn check_destination(
        &self,
        output: &Path,
        checkpoint: &impl Fn() -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        let overlaps =
            |path: &Path| self.source.starts_with(path) || path.starts_with(&self.source);
        if overlaps(output) {
            return Err(ERROR);
        }
        // Capture and recovery already require an existing parent. Resolve that
        // same boundary under the input owner, so a symlinked parent cannot hide a
        // handoff inside a derived attempt/source store. No directory is created.
        checkpoint()?;
        let parent = std::fs::canonicalize(output.parent().ok_or(ERROR)?).map_err(|_| ERROR)?;
        checkpoint()?;
        if overlaps(&parent.join(output.file_name().ok_or(ERROR)?)) {
            return Err(ERROR);
        }
        Ok(())
    }

    fn schema(&self) -> &'static str {
        match self.mode {
            CaptureMode::Single => "fss.rtsp_from_onvif_plan.v1",
            CaptureMode::Reconnect => "fss.rtsp_from_onvif_plan.v2",
        }
    }

    fn policy(&self) -> &'static str {
        match self.mode {
            CaptureMode::Single => POLICY,
            CaptureMode::Reconnect => RECONNECT_POLICY,
        }
    }

    fn digest(
        &self,
        identity: ContentDigest,
        operation: &str,
        native_approval: ContentDigest,
    ) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text(self.schema());
        encoded.text(self.policy());
        // Preserve the exact historical single-attempt approval encoding. Every
        // newly composed mode and recovery operation has a distinct v2 binding.
        if self.mode == CaptureMode::Reconnect {
            encoded.text(self.mode.as_str());
            encoded.text(operation);
        }
        encoded.text(self.source.to_str().ok_or(ERROR)?);
        encoded.digest(self.expected);
        encoded.digest(identity);
        encoded.digest(native_approval);
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| ERROR)?,
        ))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let prepared = self.read()?;
        let (native_approval, native_preview) = prepared.capture.prepared_preview()?;
        let operation = prepared.capture.operation_kind();
        Ok(object(&[
            ("schema", string(self.schema())),
            ("phase", string("planned")),
            (
                "approval",
                string(
                    &self
                        .digest(prepared.identity, operation, native_approval)?
                        .to_text(),
                ),
            ),
            ("policy", string(self.policy())),
            ("capture_mode", string(self.mode.as_str())),
            ("operation", string(operation)),
            ("onvif_source", string(self.source.to_str().ok_or(ERROR)?)),
            ("onvif_digest", string(&self.expected.to_text())),
            ("onvif_file_identity", string(&prepared.identity.to_text())),
            ("native_capture", native_preview),
            (
                "effects",
                string(if operation == "capture" {
                    "protected-handoff-and-destination-inspection-only"
                } else {
                    "protected-handoff-and-native-recovery-inspection-only"
                }),
            ),
        ]))
    }

    pub(super) fn execute(&self) -> Result<(), &'static str> {
        let prepared = self.read()?;
        let identity = prepared.identity;
        let operation = prepared.capture.operation_kind();
        // Recovery calls this once from its existing observed-state approval gate
        // with all original owners held. Do not preview first: that would rescan
        // source data with a fresh work budget and restart the recovery deadline.
        prepared.capture.execute(&|native_approval| {
            if self.approval != Some(self.digest(identity, operation, native_approval)?) {
                return Err("ERR-CAPTURE-ONVIF-APPROVAL-001");
            }
            // Recheck the exact protected bytes, schema, private permissions and
            // fingerprint after observation and before authorizing native work.
            if self.read()?.identity != identity {
                return Err("ERR-CAPTURE-ONVIF-APPROVAL-001");
            }
            Ok(())
        })
    }
}
