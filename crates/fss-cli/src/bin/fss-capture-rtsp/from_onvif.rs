#![forbid(unsafe_code)]
//! Protected ONVIF metadata becomes an ordinary, separately approved capture plan.
//! The file provides only the exact route and codec, never source/timing authority.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, PrincipalId};

use super::driver;
use super::plan::{self, Options};

#[path = "../fss-onvif/handoff.rs"]
mod handoff;
#[path = "../fss-onvif/private_file.rs"]
mod private_file;
#[path = "../fss-onvif/runtime.rs"]
mod runtime;

const ERROR: &str = "ERR-CAPTURE-ONVIF-HANDOFF-001";
const POLICY: &str = "private-digest-bound-stable-onvif-uri:separate-owner-capture-approval:\
unchanged-source-clock-timing-and-independent-pin-owners:no-camera-or-credential-read-in-preview:v1";

pub(super) const HELP: &str = "fss-capture-rtsp from-onvif\n\
  --onvif-source /PRIVATE_HANDOFF --onvif-digest sha256:HEX\n\
  --control-root /OWNER_APPROVED_TRACK_SUBTREE [ordinary capture source/timing/store options]\n\
  [--approve sha256:HEX]\n\
\n\
This mode reads only the exact private handoff produced by approved `fss-onvif --profile ...`.\n\
Supply its output_digest from the safe result. Preview reads bounded protected metadata through\n\
an owned context, opens no camera or credentials, and emits a new capture approval. Repeat all\n\
options with that approval. File content, identity, permissions and digest are checked again\n\
before entering the existing native capture owner. No source/timing identity is inferred.\n\
\n\
The handoff supplies peer, authority, exact presentation URI and AVC codec. Do not supply\n\
--peer, --authority, --presentation or --codec. The owner must supply --control-root plus\n\
all ordinary required sensor/stream/generation/ingress/SSRC, source and clock digests, cadence,\n\
new archive and independent pin-journal paths, budgets and original-retention authorization.\n\
Queries and safe percent escapes are preserved exactly and redacted from stdout. The control\n\
root remains an explicit query-free subtree; camera metadata cannot authorize sibling tracks.\n\
RTSP Digest, if needed, requires its own --credential-file and exact --auth-realm options.\n\
\n\
Only stable H.264 Media1 handoffs are accepted. Inventory files, unsupported codecs, expiring\n\
URIs, embedded credentials, altered files, symlinks and nonprivate permissions refuse.\n\
The handoff grants no recording, source custody, clock, identity or conformance authority.\n\
This initial mode runs one ordinary capture attempt; reconnect, retained-source and recovery\n\
wrappers require their own explicit plans and are not enabled by the handoff.\n";

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
        if args.len() > plan::MAX_ARGUMENTS + 4
            || !args.len().is_multiple_of(2)
            || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
        {
            return Err(ERROR);
        }
        let mut source = None;
        let mut expected = None;
        let mut approval = None;
        let mut principal = "principal:local-operator".to_owned();
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
            let capture = Options::parse(&args)?;
            if [&capture.root, &capture.pins]
                .iter()
                .any(|output| self.source.starts_with(output) || output.starts_with(&self.source))
            {
                return Err(ERROR);
            }
            input.revalidate(&|| scope.input())?;
            Ok(Prepared {
                capture,
                identity: ContentDigest::sha256(&input.fingerprint()),
            })
        })
    }

    fn digest(&self, prepared: &Prepared) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        encoded.text("fss.rtsp_from_onvif_plan.v1");
        encoded.text(POLICY);
        encoded.text(self.source.to_str().ok_or(ERROR)?);
        encoded.digest(self.expected);
        encoded.digest(prepared.identity);
        encoded.digest(prepared.capture.digest()?);
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| ERROR)?,
        ))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let prepared = self.read()?;
        Ok(object(&[
            ("schema", string("fss.rtsp_from_onvif_plan.v1")),
            ("phase", string("planned")),
            ("approval", string(&self.digest(&prepared)?.to_text())),
            ("policy", string(POLICY)),
            ("onvif_source", string(self.source.to_str().ok_or(ERROR)?)),
            ("onvif_digest", string(&self.expected.to_text())),
            ("onvif_file_identity", string(&prepared.identity.to_text())),
            ("native_capture", prepared.capture.private_uri_preview()?),
            ("effects", string("protected-handoff-read-only")),
        ]))
    }

    pub(super) fn execute(&self) -> Result<(), &'static str> {
        let prepared = self.read()?;
        if self.approval != Some(self.digest(&prepared)?) {
            return Err("ERR-CAPTURE-ONVIF-APPROVAL-001");
        }
        // Only the exact outer plan may delegate to the established native owner.
        let mut capture = prepared.capture;
        capture.approve = Some(capture.digest()?);
        driver::execute(&capture)
    }
}
