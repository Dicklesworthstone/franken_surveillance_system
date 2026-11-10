#![forbid(unsafe_code)]
//! An exact private recorder selection delegates one separately approved native replay.
//! The observed recording never supplies source identities, clock authority, or custody.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fss_cli::onvif_plan::ProtectedOnvifInput;
use fss_cli::onvif_replay_plan::{
    ERR_CAPTURE_ONVIF_REPLAY, OnvifReplaySourceSpec, parse_digest,
};
use fss_core::{ContentDigest, PrincipalId};

use super::driver;
use super::from_onvif::{private_file, runtime};
use super::plan::Options;

const APPROVAL: &str = "ERR-CAPTURE-ONVIF-REPLAY-APPROVAL-001";
pub(super) const MAX_ARGUMENTS: usize = super::plan::MAX_ARGUMENTS + 6;

pub(super) const HELP: &str = "fss-capture-rtsp from-onvif-replay\n\
  --onvif-source /PRIVATE_REPLAY_HANDOFF --onvif-digest sha256:HEX\n\
  (--control-root /OWNER_APPROVED_TRACK_SUBTREE | --onvif-control-root-digest sha256:HEX)\n\
  [ordinary single capture source/timing/store options]\n\
  [--approve sha256:HEX]\n\
\n\
Reads the exact private file produced by approved fss-onvif replay. Preview opens no\n\
recorder, credentials or output store. Approve the OUTER preview digest and repeat all options.\n\
The actual input bytes, private permissions and file identity are checked again immediately\n\
before native capture. Replacing the file requires a new preview, even with identical bytes.\n\
\n\
The handoff supplies the independently scoped RTSP peer/authority, exact URI, explicit AVC or\n\
HEVC codec and closed replay interval. Do not supply --peer, --authority, --presentation,\n\
--codec, --replay-start or --replay-end. The owner supplies the SDP control subtree, exact\n\
sensor/stream/generation/ingress/SSRC, source and clock digests, cadence, fresh archive and pin\n\
journal paths, budgets and original-retention authorization. Digest authentication, if needed,\n\
requires an independent --credential-file and exact --auth-realm. One bounded native attempt\n\
is supported; reconnect, recovery and supervised wrapper options are refused.\n\
\n\
The requested interval is never clipped. Known advertised bounds must contain it; missing\n\
bounds remain unknown. Advertised extrema never prove continuity or complete retrieval.\n\
The replay URI lifetime remains unknown. There is no automatic live fallback or rediscovery.\n\
The durable replay receipt binds the original selection, protected input fingerprint, native\n\
request and exact outer approval. Independently pin its root, request and scope for later\n\
fss-archive inspect-replay. The receipt does not require the private handoff for cold reads.\n";

pub(super) struct SourcePlan {
    source: PathBuf,
    expected: ContentDigest,
    approval: Option<ContentDigest>,
    principal: String,
    capture_args: Vec<OsString>,
}

struct Prepared {
    capture: Options,
    identity: ContentDigest,
}

impl SourcePlan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > MAX_ARGUMENTS
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        let mut source = None;
        let mut expected = None;
        let mut approval = None;
        let mut principal = "principal:local-operator".to_owned();
        let mut capture_args = Vec::new();
        let mut seen = BTreeSet::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?;
            let value = pair[1].to_str().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?;
            if value.is_empty() || !seen.insert(key) {
                return Err(ERR_CAPTURE_ONVIF_REPLAY);
            }
            match key {
                "--onvif-source" => source = Some(private_file::absolute_path(value)?),
                "--onvif-digest" => expected = Some(parse_digest(value)?),
                "--approve" => approval = Some(parse_digest(value)?),
                "--peer" | "--authority" | "--presentation" | "--codec"
                | "--replay-start" | "--replay-end" | "--capture-mode" | "--recover" => {
                    return Err(ERR_CAPTURE_ONVIF_REPLAY);
                }
                _ => {
                    if key == "--principal" {
                        principal = value.to_owned();
                    }
                    capture_args.extend_from_slice(pair);
                }
            }
        }
        PrincipalId::parse(&principal).map_err(|_| ERR_CAPTURE_ONVIF_REPLAY)?;
        if principal.len() > 256 {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        Ok(Self {
            source: source.ok_or(ERR_CAPTURE_ONVIF_REPLAY)?,
            expected: expected.ok_or(ERR_CAPTURE_ONVIF_REPLAY)?,
            approval,
            principal,
            capture_args,
        })
    }

    pub(super) fn approved(&self) -> bool {
        self.approval.is_some()
    }

    fn spec(&self) -> OnvifReplaySourceSpec {
        OnvifReplaySourceSpec {
            source: self.source.clone(),
            expected: self.expected,
        }
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
            let fingerprint = input.fingerprint();
            let selected = self.spec().prepare(
                ProtectedOnvifInput {
                    bytes: input.bytes(),
                    fingerprint: &fingerprint,
                },
                &self.capture_args,
            )?;
            let capture = selected.with_capture_arguments(|args| {
                Options::parse_with_replay_source(args, Some(selected.source_binding().clone()))
            })?;
            for output in [&capture.root, &capture.pins] {
                self.check_destination(output, &|| scope.input())?;
            }
            input.revalidate(&|| scope.input())?;
            Ok(Prepared {
                capture,
                identity: selected.file_identity(),
            })
        })
    }

    fn check_destination(
        &self,
        output: &Path,
        checkpoint: &impl Fn() -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        let overlaps = |path: &Path| self.source.starts_with(path) || path.starts_with(&self.source);
        if overlaps(output) {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        checkpoint()?;
        let parent = std::fs::canonicalize(output.parent().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?)
            .map_err(|_| ERR_CAPTURE_ONVIF_REPLAY)?;
        checkpoint()?;
        if overlaps(&parent.join(output.file_name().ok_or(ERR_CAPTURE_ONVIF_REPLAY)?)) {
            return Err(ERR_CAPTURE_ONVIF_REPLAY);
        }
        Ok(())
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let prepared = self.read()?;
        self.spec().preview(
            prepared.identity,
            prepared.capture.digest()?,
            &prepared.capture.private_uri_preview()?,
        )
    }

    pub(super) fn execute(&self) -> Result<(), &'static str> {
        let mut prepared = self.read()?;
        let native = prepared.capture.digest()?;
        let outer = self.spec().approval(prepared.identity, native)?;
        if self.approval != Some(outer) {
            return Err(APPROVAL);
        }
        // Fresh input ownership checks the pathname, complete bytes, schema and private-file
        // fingerprint again. Neither a nested native approval nor a file replacement can grant
        // this wrapper authority, even when the replacement contains identical bytes.
        let current = self.read()?;
        if current.identity != prepared.identity || current.capture.digest()? != native {
            return Err(APPROVAL);
        }
        prepared.capture.approve_protected_replay(outer)?;
        driver::execute(&prepared.capture)
    }
}
