#![forbid(unsafe_code)]
//! Private, capability-driven UniFi Protect selection enters the existing capture owner.
//! Exported camera metadata is neither current liveness nor capture/effect authority.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::rtsp::client::validated_uri_parts;
use fss_reference::unifi::{
    ProtectError, ProtectQuality, ProtectSource, ProtectView, TransportChoice,
};

use super::from_onvif::{CaptureMode, NativeCapture, private_file, runtime};

const ERROR: &str = "ERR-CAPTURE-UNIFI-SOURCE-001";
const APPROVAL: &str = "ERR-CAPTURE-UNIFI-APPROVAL-001";
const TRANSPORT: &str = "ERR-CAPTURE-UNIFI-TRANSPORT-001";
const ROUTE: &str = "ERR-CAPTURE-UNIFI-ROUTE-001";
const SCHEMA: &str = "fss.rtsp_from_unifi_plan.v1";
const POLICY: &str = "private-unifi-protect-capability-selected-view:exact-owner-peer:explicit-codec-and-cadence:\
no-url-rewrite:no-quality-fallback:no-tls-downgrade:revalidate-private-source-before-capture:v1";

pub(super) const MAX_ARGUMENTS: usize = super::reconnect::MAX_ARGUMENTS + 12;
pub(super) const HELP: &str = "fss-capture-rtsp from-unifi\n\
  --unifi-source /PRIVATE_JSON --unifi-digest sha256:HEX --quality high|medium|low|package\n\
  --peer IP:PORT --codec avc|hevc [ordinary capture source/timing/store options]\n\
  [--stream-transport published|operator-rtsp] [--control-root /EXACT_SUBTREE]\n\
  [--capture-mode single|reconnect] [--approve sha256:HEX]\n\
\n\
The private JSON contains {\"camera\": CAMERA, \"streams\": STREAMS, \"rtsp\": OPTIONAL_RTSP_URLS}.\n\
CAMERA is one official Protect GET /v1/cameras item or GET /v1/cameras/{id} response.\n\
STREAMS is the GET /v1/cameras/{id}/rtsps-stream object with nullable high/medium/low/package.\n\
The optional rtsp object contains independently obtained, owner-verified plaintext URLs.\n\
Do not include API keys, cookies, passwords or Authorization fields. Protect stream tokens\n\
remain in the private file, never argv or stdout. File permissions must be owner-only;\n\
symlinks, hard links, identity/content changes and oversized files are refused. Linux only.\n\
\n\
Published (default) uses the exact selected URL. RTSPS requires TLS and is explicitly refused\n\
by this plaintext capture owner. No scheme, port, path or query is rewritten. An operator\n\
who has independently verified an RTSP endpoint can select --stream-transport operator-rtsp\n\
and provide that URL in rtsp, together with the existing --plaintext yes acknowledgement.\n\
The literal --peer must match the selected URL's port and its IP when the URL has an IP host.\n\
No DNS, API login, stream enablement, camera setting change, or alternate route is attempted.\n\
\n\
All models use their reported capabilities. Package quality requires hasPackageCamera=true\n\
and remains a distinct view. Disabled, missing and unsupported qualities never fall back.\n\
An exported connection state is historical metadata, not proof of current camera liveness.\n\
The caller supplies --codec, exact cadence, unique sensor/stream identity per view, generation,\n\
source/clock/timing evidence, original-retention authorization and new archive/pin paths.\n\
Do not supply --authority or --presentation: they come from the private selected endpoint.\n\
The default control root is its exact path without the query; any wider root is explicit.\n\
\n\
Without --approve, inspect only the protected source and destination parents and print a\n\
redacted approval plan. Repeat all options with its OUTER approval to use existing bounded\n\
native AVC/HEVC recording, importable archives, private preview and optional reconnect.\n\
File contents, identity and permissions are rechecked before native work. Recovery is the\n\
existing explicit reconnect recovery protocol and never resumes camera capture. Preserve\n\
all stores and JSONL receipts. This integration is implemented, not hardware-qualified.\n";

pub(super) fn remediation(code: &str) -> &'static str {
    match code {
        TRANSPORT => {
            "This recorder requires an explicitly selected plaintext RTSP endpoint. RTSPS is not downgraded; use a separately verified operator-rtsp URL or a qualified secure transport."
        }
        ROUTE => {
            "The selected URL and literal peer do not match. Correct the exact owner-approved address and port; no alternate route is attempted."
        }
        "ERR-CAPTURE-UNIFI-STREAM-MISSING-001" => {
            "The selected stream was omitted. Refresh the complete stream export or select an explicitly available quality; no fallback occurred."
        }
        "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001" => {
            "The selected quality has no enabled URL. Enable it through the owner's Protect interface and refresh the export; FSS changes no camera settings."
        }
        "ERR-CAPTURE-UNIFI-PACKAGE-001" => {
            "The camera did not explicitly report package-camera capability. Select a supported main quality or refresh the camera export."
        }
        APPROVAL => {
            "The exact source identity, selection or native plan changed. Preview again and approve the complete current plan."
        }
        _ => {
            "Inspect the private source and exact plan. Preserve any archive, independent pin journal and JSONL receipts if capture began; use from-unifi --help."
        }
    }
}

pub(super) struct SourcePlan {
    source: PathBuf,
    expected: ContentDigest,
    approval: Option<ContentDigest>,
    principal: String,
    quality: ProtectQuality,
    transport: TransportChoice,
    mode: CaptureMode,
    peer: SocketAddr,
    has_control_root: bool,
    capture_args: Vec<OsString>,
}

struct Prepared {
    capture: NativeCapture,
    identity: ContentDigest,
    camera: ContentDigest,
    view: &'static str,
}

fn digest(value: &str) -> Result<ContentDigest, &'static str> {
    let parsed = ContentDigest::parse(value).map_err(|_| ERROR)?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 || parsed.bytes() == [0; 32] {
        return Err(ERROR);
    }
    Ok(parsed)
}

fn selection_error(error: ProtectError) -> &'static str {
    match error {
        ProtectError::MissingStream(_) => "ERR-CAPTURE-UNIFI-STREAM-MISSING-001",
        ProtectError::DisabledStream(_) => "ERR-CAPTURE-UNIFI-STREAM-DISABLED-001",
        ProtectError::PackageUnavailable => "ERR-CAPTURE-UNIFI-PACKAGE-001",
        ProtectError::MissingOperatorRtsp | ProtectError::NonRtspOverride => TRANSPORT,
        ProtectError::SecureTransportRequired => TRANSPORT,
        _ => ERROR,
    }
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
        let mut quality = None;
        let mut transport = TransportChoice::Published;
        let mut mode = CaptureMode::Single;
        let mut peer = None;
        let mut has_control_root = false;
        let mut has_codec = false;
        let mut capture_args = Vec::new();
        let mut seen = BTreeSet::new();
        for pair in args.as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or(ERROR)?;
            let value = pair[1].to_str().ok_or(ERROR)?;
            if value.is_empty() || !seen.insert(key) {
                return Err(ERROR);
            }
            match key {
                "--unifi-source" => source = Some(private_file::absolute_path(value)?),
                "--unifi-digest" => expected = Some(digest(value)?),
                "--approve" => approval = Some(digest(value)?),
                "--quality" => {
                    quality = Some(match value {
                        "high" => ProtectQuality::High,
                        "medium" => ProtectQuality::Medium,
                        "low" => ProtectQuality::Low,
                        "package" => ProtectQuality::Package,
                        _ => return Err(ERROR),
                    });
                }
                "--stream-transport" => {
                    transport = match value {
                        "published" => TransportChoice::Published,
                        "operator-rtsp" => TransportChoice::OperatorRtsp,
                        _ => return Err(ERROR),
                    };
                }
                "--capture-mode" => {
                    mode = match value {
                        "single" => CaptureMode::Single,
                        "reconnect" => CaptureMode::Reconnect,
                        _ => return Err(ERROR),
                    };
                }
                "--authority" | "--presentation" => return Err(ERROR),
                _ => {
                    match key {
                        "--principal" => principal = value.to_owned(),
                        "--peer" => peer = Some(value.parse::<SocketAddr>().map_err(|_| ERROR)?),
                        "--control-root" => has_control_root = true,
                        "--codec" => has_codec = matches!(value, "avc" | "hevc"),
                        _ => {}
                    }
                    capture_args.extend_from_slice(pair);
                }
            }
        }
        PrincipalId::parse(&principal).map_err(|_| ERROR)?;
        if principal.len() > 256 || !has_codec {
            return Err(ERROR);
        }
        Ok(Self {
            source: source.ok_or(ERROR)?,
            expected: expected.ok_or(ERROR)?,
            approval,
            principal,
            quality: quality.ok_or(ERROR)?,
            transport,
            mode,
            peer: peer.ok_or(ERROR)?,
            has_control_root,
            capture_args,
        })
    }

    pub(super) fn approved(&self) -> bool {
        self.approval.is_some()
    }

    fn quality(&self) -> &'static str {
        match self.quality {
            ProtectQuality::High => "high",
            ProtectQuality::Medium => "medium",
            ProtectQuality::Low => "low",
            ProtectQuality::Package => "package",
        }
    }

    fn transport(&self) -> &'static str {
        match self.transport {
            TransportChoice::Published => "published",
            TransportChoice::OperatorRtsp => "operator-rtsp",
        }
    }

    fn read(&self) -> Result<Prepared, &'static str> {
        runtime::run(
            runtime::Request {
                approval: self.expected,
                principal: self.principal.clone(),
                timeout_ns: 5_000_000_000,
                bytes: private_file::MAX_FILE_BYTES as u64 + 8192,
                network_bytes: 0,
                storage_operations: 8192,
                network: false,
                write: false,
                secrets: false,
            },
            |scope| {
                let input = private_file::InputLease::open(&self.source, &|| scope.input())?;
                if ContentDigest::sha256(input.bytes()) != self.expected {
                    return Err(ERROR);
                }
                let source = ProtectSource::parse(input.bytes()).map_err(selection_error)?;
                let selected = source
                    .select(self.quality, self.transport)
                    .map_err(selection_error)?;
                let endpoint = selected.endpoint();
                let uri = endpoint.require_plaintext_rtsp().map_err(|_| TRANSPORT)?;
                let (authority, presentation) = validated_uri_parts(uri).map_err(|_| ERROR)?;
                if endpoint.port().unwrap_or(554) != self.peer.port()
                    || endpoint
                        .host()
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| ip != self.peer.ip())
                {
                    return Err(ROUTE);
                }
                let mut args = self.capture_args.clone();
                for (key, value) in [("--authority", authority), ("--presentation", presentation)] {
                    args.extend([OsString::from(key), OsString::from(value)]);
                }
                if !self.has_control_root {
                    let path = presentation.split('?').next().ok_or(ERROR)?;
                    args.extend([OsString::from("--control-root"), OsString::from(path)]);
                }
                let capture = NativeCapture::parse(self.mode, &args)?;
                for output in capture.paths()? {
                    self.check_destination(output, &|| scope.input())?;
                }
                input.revalidate(&|| scope.input())?;
                Ok(Prepared {
                    capture,
                    identity: ContentDigest::sha256(&input.fingerprint()),
                    camera: ContentDigest::sha256(selected.camera().id().as_bytes()),
                    view: match selected.view() {
                        ProtectView::Main => "main",
                        ProtectView::Package => "package",
                    },
                })
            },
        )
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
        checkpoint()?;
        let parent = std::fs::canonicalize(output.parent().ok_or(ERROR)?).map_err(|_| ERROR)?;
        checkpoint()?;
        if overlaps(&parent.join(output.file_name().ok_or(ERROR)?)) {
            return Err(ERROR);
        }
        Ok(())
    }

    fn digest(
        &self,
        identity: ContentDigest,
        operation: &str,
        native: ContentDigest,
    ) -> Result<ContentDigest, &'static str> {
        let mut encoded = CanonicalEncoder::new();
        // Extend the registered capture-approval family with a distinct selection policy.
        encoded.text("fss.rtsp_capture_cli_plan.v1");
        encoded.text(POLICY);
        encoded.text(self.source.to_str().ok_or(ERROR)?);
        encoded.digest(self.expected);
        encoded.digest(identity);
        encoded.text(self.quality());
        encoded.text(self.transport());
        encoded.text(self.mode.as_str());
        encoded.text(operation);
        encoded.digest(native);
        Ok(ContentDigest::sha256(
            &encoded.finish_checked().map_err(|_| ERROR)?,
        ))
    }

    pub(super) fn preview(&self) -> Result<String, &'static str> {
        let prepared = self.read()?;
        let (native, preview) = prepared.capture.prepared_preview()?;
        let operation = prepared.capture.operation_kind();
        Ok(object(&[
            ("schema", string(SCHEMA)),
            ("phase", string("planned")),
            (
                "approval",
                string(&self.digest(prepared.identity, operation, native)?.to_text()),
            ),
            ("policy", string(POLICY)),
            ("quality", string(self.quality())),
            ("view", string(prepared.view)),
            ("camera_ref", string(&prepared.camera.to_text())),
            ("stream_transport", string(self.transport())),
            ("capture_mode", string(self.mode.as_str())),
            ("operation", string(operation)),
            ("unifi_digest", string(&self.expected.to_text())),
            ("unifi_file_identity", string(&prepared.identity.to_text())),
            ("native_capture", preview),
            ("model_specific_assumptions", "false".into()),
            ("hardware_qualified", "false".into()),
            ("effects_started", "false".into()),
        ]))
    }

    pub(super) fn execute(&self) -> Result<(), &'static str> {
        let prepared = self.read()?;
        let identity = prepared.identity;
        let operation = prepared.capture.operation_kind();
        prepared.capture.execute(&|native| {
            if self.approval != Some(self.digest(identity, operation, native)?) {
                return Err(APPROVAL);
            }
            if self.read()?.identity != identity {
                return Err(APPROVAL);
            }
            Ok(())
        })
    }
}
