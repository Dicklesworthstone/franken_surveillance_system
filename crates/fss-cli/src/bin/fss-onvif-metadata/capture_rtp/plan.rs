#![forbid(unsafe_code)]
//! Pure owner approval and bounds for one native RTSP metadata acquisition.
//! Parsing does not read credentials, create storage, resolve names or open a socket.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use fss_core::{CanonicalEncoder, CaptureInterval, ContentDigest, SensorId, TimestampNs};
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_reference::onvif::metadata::SourceBinding;
use fss_reference::onvif::metadata::rtp::{RtpMetadataConfig, RtpMetadataImportLimits};
use fss_reference::rtsp::client::ClientConfig;
use fss_reference::rtsp::metadata_source::{
    MAX_RECORDS, MAX_SOURCE_BYTES, NativeMetadataConfig, NativeMetadataSource,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};

use super::super::authentication::AuthPlan;
use super::super::{ARGUMENT_ERROR, clean_absolute, digest, text};

pub(super) const HELP: &str = "fss-onvif-metadata capture-rtp [options]
  --root ABSOLUTE_DIR --site SITE --sensor ID
  --device-generation sha256:HEX --profile-generation sha256:HEX --profile TOKEN
  --peer IP:PORT --authority HOST[:PORT] --url rtsp://HOST/PRESENTATION
  --control-root rtsp://HOST/SUBTREE --media-index N
  --ingress N --stream-generation N --ssrc N --payload-type N
  --receive-origin-ns N --owner-authorized yes --plaintext yes --retain-source yes
  [--principal ID] [--capture-ms 5000] [--timeout-ms 30000]
  [--max-documents 16] [--max-source-bytes 1048576] [--max-records 4096]
  [--rtp-channel 0] [--max-document-bytes 262144] [--max-fragments 4096]
  [--document-timeout-ms 2000] [--reorder-delay-ms 100]
  [--credential-file /PRIVATE_FILE --auth-realm EXACT_REALM]
  [--legacy-md5 yes] [--legacy-no-qop yes]

Acquires one finite owner-selected uncompressed ONVIF metadata track using RTSP/TCP.
The peer must be a literal IP:port; authority, control subtree, media index, stream
generation, SSRC and dynamic payload type 96..127 are independently pinned.
No automatic reconnect, discovery, compressed metadata or credential-bearing URLs.
Optional Digest credentials use a private regular file: username newline password
newline. MD5 and legacy no-qop require their explicit flags; Basic is unsupported.
Capture includes negotiation and is bounded to 45 seconds. The total timeout is at
most 60 seconds and must leave at least five seconds beyond capture for publication
and cleanup. Source retention is bounded to 8 MiB and 16,384 complete frames; at
most 64 complete XML documents are requested. Every limit remains independently
enforced, so a document target is not a promise that the target will be observed.
The source witness retains exact accepted SDP, complete interleaved frames, original
receive nanoseconds and hash-only control observations. Raw TCP chunks, authentication
and session headers are not retained. Bounded omissions remain explicit.
--receive-origin-ns is the owner-declared clock at monotonic request zero; camera
timestamps remain unverified claims. The rtpdump replay is a separate millisecond
projection. Partial captures and known durable roots remain inspectable with
inspect-rtp or verify-rtp. Private vendor values are withheld during capture.
This command does not establish source authenticity, physical coverage or absence.
";

/// Validated owner intent only; the runtime must recheck authority at every effect.
pub(super) struct Options {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    pub(super) approval: ContentDigest,
    /// Placeholder receive interval at monotonic zero; the driver replaces it with
    /// origin + the actual retained source start/end observations before publication.
    pub(super) binding: SourceBinding,
    pub(super) protocol: ClientConfig,
    pub(super) tcp: TcpBinding,
    pub(super) payload_type: u8,
    pub(super) receive_origin_ns: i128,
    pub(super) timeout_ns: u64,
    pub(super) capture_ns: u64,
    pub(super) max_documents: usize,
    pub(super) max_source_bytes: usize,
    pub(super) max_records: usize,
    pub(super) config: RtpMetadataConfig,
    pub(super) auth: Option<AuthPlan>,
}

fn number(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: Option<u128>,
    min: u128,
    max: u128,
) -> Result<u128, &'static str> {
    let value = match values.get(key) {
        Some(value) => value
            .to_str()
            .ok_or(ARGUMENT_ERROR)?
            .parse::<u128>()
            .map_err(|_| ARGUMENT_ERROR)?,
        None => default.ok_or(ARGUMENT_ERROR)?,
    };
    if !(min..=max).contains(&value) {
        return Err(ARGUMENT_ERROR);
    }
    Ok(value)
}

fn private_path(value: &str) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(value);
    if clean_absolute(&path) {
        Ok(path)
    } else {
        Err(ARGUMENT_ERROR)
    }
}

pub(super) fn parse(args: &[OsString]) -> Result<Option<Options>, &'static str> {
    if args == [OsString::from("capture-rtp")]
        || args == [OsString::from("capture-rtp"), OsString::from("--help")]
        || args == [OsString::from("capture-rtp"), OsString::from("-h")]
    {
        return Ok(None);
    }
    if args.is_empty()
        || args[0] != "capture-rtp"
        || args.len() > 69
        || args.len() % 2 != 1
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(ARGUMENT_ERROR);
    }
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let key = pair[0].to_str().ok_or(ARGUMENT_ERROR)?;
        if !matches!(
            key,
            "--root"
                | "--site"
                | "--principal"
                | "--sensor"
                | "--device-generation"
                | "--profile-generation"
                | "--profile"
                | "--peer"
                | "--authority"
                | "--url"
                | "--control-root"
                | "--media-index"
                | "--ingress"
                | "--stream-generation"
                | "--ssrc"
                | "--payload-type"
                | "--receive-origin-ns"
                | "--owner-authorized"
                | "--plaintext"
                | "--retain-source"
                | "--capture-ms"
                | "--timeout-ms"
                | "--max-documents"
                | "--max-source-bytes"
                | "--max-records"
                | "--rtp-channel"
                | "--max-document-bytes"
                | "--max-fragments"
                | "--document-timeout-ms"
                | "--reorder-delay-ms"
                | "--credential-file"
                | "--auth-realm"
                | "--legacy-md5"
                | "--legacy-no-qop"
        ) || values.insert(key.to_owned(), pair[1].clone()).is_some()
        {
            return Err(ARGUMENT_ERROR);
        }
    }
    for key in ["--owner-authorized", "--plaintext", "--retain-source"] {
        if text(&values, key)? != "yes" {
            return Err(ARGUMENT_ERROR);
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or(ARGUMENT_ERROR)?);
    if !clean_absolute(&root) {
        return Err(ARGUMENT_ERROR);
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| ARGUMENT_ERROR)?;
    if site.len() > 256 {
        return Err(ARGUMENT_ERROR);
    }
    let principal = values
        .get("--principal")
        .map_or(Ok("operator:local-onvif-metadata"), |value| {
            value.to_str().ok_or(ARGUMENT_ERROR)
        })?
        .to_owned();
    if principal.is_empty()
        || principal.len() > 256
        || principal.trim() != principal
        || principal.chars().any(char::is_control)
    {
        return Err(ARGUMENT_ERROR);
    }
    let capture_ns = number(&values, "--capture-ms", Some(5000), 1, 45000)? as u64 * 1_000_000;
    let timeout_ns = number(&values, "--timeout-ms", Some(30000), 1000, 60000)? as u64 * 1_000_000;
    if timeout_ns < capture_ns + 5_000_000_000 {
        return Err(ARGUMENT_ERROR);
    }
    let receive_origin_ns = text(&values, "--receive-origin-ns")?
        .parse::<i128>()
        .map_err(|_| ARGUMENT_ERROR)?;
    if receive_origin_ns < 0
        || receive_origin_ns
            .checked_add(i128::from(timeout_ns))
            .is_none()
    {
        return Err(ARGUMENT_ERROR);
    }
    let binding = SourceBinding {
        sensor_id: SensorId::parse(text(&values, "--sensor")?).map_err(|_| ARGUMENT_ERROR)?,
        device_generation: digest(text(&values, "--device-generation")?)?,
        profile_generation: digest(text(&values, "--profile-generation")?)?,
        profile_token: text(&values, "--profile")?.to_owned(),
        receive_interval: CaptureInterval::new(
            TimestampNs(receive_origin_ns),
            TimestampNs(receive_origin_ns),
        )
        .map_err(|_| ARGUMENT_ERROR)?,
    };
    binding.validate().map_err(|_| ARGUMENT_ERROR)?;
    let stream = StreamKey {
        ingress: number(&values, "--ingress", None, 1, u128::MAX)?,
        generation: number(&values, "--stream-generation", None, 1, u64::MAX as u128)? as u64,
        ssrc: number(&values, "--ssrc", None, 0, u32::MAX as u128)? as u32,
    };
    let payload_type = number(&values, "--payload-type", None, 96, 127)? as u8;
    let rtp_channel = number(&values, "--rtp-channel", Some(0), 0, 254)? as u8;
    let protocol = ClientConfig {
        presentation_uri: text(&values, "--url")?.to_owned(),
        control_root_uri: text(&values, "--control-root")?.to_owned(),
        media_index: number(&values, "--media-index", None, 0, 63)? as usize,
        channels: (rtp_channel, rtp_channel + 1),
        response_timeout_ns: capture_ns.min(5_000_000_000),
        default_session_timeout_seconds: 60,
    };
    let tcp = TcpBinding::new(
        stream,
        text(&values, "--peer")?
            .parse::<SocketAddr>()
            .map_err(|_| ARGUMENT_ERROR)?,
        text(&values, "--authority")?,
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )
    .map_err(|_| ARGUMENT_ERROR)?;
    let max_documents = number(&values, "--max-documents", Some(16), 1, 64)? as usize;
    let max_source_bytes = number(
        &values,
        "--max-source-bytes",
        Some(1024 * 1024),
        1,
        MAX_SOURCE_BYTES as u128,
    )? as usize;
    let max_records =
        number(&values, "--max-records", Some(4096), 1, MAX_RECORDS as u128)? as usize;
    let config = RtpMetadataConfig {
        stream,
        payload_type,
        limits: RtpMetadataImportLimits {
            max_input_bytes: max_source_bytes,
            max_records,
            max_documents,
        },
        reorder: ReorderLimits {
            max_delay_ns: number(&values, "--reorder-delay-ms", Some(100), 1, 60000)? as u64
                * 1_000_000,
            ..ReorderLimits::default()
        },
        metadata: OnvifMetadataLimits {
            max_document_bytes: number(&values, "--max-document-bytes", Some(262144), 1, 262144)?
                as usize,
            max_fragment_packets: number(&values, "--max-fragments", Some(4096), 1, 4096)? as usize,
            max_pending_age_ns: number(&values, "--document-timeout-ms", Some(2000), 1, 60000)?
                as u64
                * 1_000_000,
        },
    };
    config.validate().map_err(|_| ARGUMENT_ERROR)?;
    let auth_values = [
        "--credential-file",
        "--auth-realm",
        "--legacy-md5",
        "--legacy-no-qop",
    ]
    .into_iter()
    .filter_map(|key| values.get(key).map(|value| (key, value)))
    .map(|(key, value)| Ok((key, value.to_str().ok_or(ARGUMENT_ERROR)?)))
    .collect::<Result<BTreeMap<_, _>, &'static str>>()?;
    let auth = AuthPlan::parse(&auth_values, private_path).map_err(|_| ARGUMENT_ERROR)?;

    // Defaults are bound as well as exact sorted arguments. The credential path is
    // only a reference; the parser never reads, hashes or retains credential values.
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.onvif_metadata_native_request.v1");
    encoder.text("one-rtsp-tcp-metadata-source:no-automatic-reconnect");
    encoder.u32(values.len() as u32);
    for (key, value) in &values {
        encoder.text(key);
        encoder.bytes(value.as_encoded_bytes());
    }
    encoder.text(&principal);
    for value in [
        timeout_ns,
        capture_ns,
        max_documents as u64,
        max_source_bytes as u64,
        max_records as u64,
        protocol.response_timeout_ns,
        u64::from(protocol.default_session_timeout_seconds),
        config.reorder.packet.max_packet_bytes as u64,
        config.reorder.packet.max_extension_bytes as u64,
        config.reorder.packet.max_rtcp_packets as u64,
        config.reorder.max_packets as u64,
        config.reorder.max_bytes as u64,
        config.reorder.max_delay_ns,
        config.metadata.max_document_bytes as u64,
        config.metadata.max_fragment_packets as u64,
        config.metadata.max_pending_age_ns,
    ] {
        encoder.u64(value);
    }
    encoder.u8(rtp_channel);
    encoder.u8(rtp_channel + 1);
    encoder.bool(auth.is_some());
    if let Some(auth) = &auth {
        encoder.digest(ContentDigest::sha256(auth.realm.as_bytes()));
        encoder.bool(auth.policy.allow_legacy_md5);
        encoder.bool(auth.policy.allow_legacy_no_qop);
    }
    let approval = ContentDigest::sha256(&encoder.finish_checked().map_err(|_| ARGUMENT_ERROR)?);
    // Real pure source/session validation also checks scope, exact authority,
    // metadata payload selection and whether the complete envelope fits its cap.
    NativeMetadataSource::new(NativeMetadataConfig {
        approval,
        protocol: protocol.clone(),
        binding: tcp.clone(),
        payload_type,
        receive_origin_ns,
        started_ns: 0,
        max_source_bytes,
        max_records,
    })
    .map_err(|_| ARGUMENT_ERROR)?;
    Ok(Some(Options {
        root,
        site,
        principal,
        approval,
        binding,
        protocol,
        tcp,
        payload_type,
        receive_origin_ns,
        timeout_ns,
        capture_ns,
        max_documents,
        max_source_bytes,
        max_records,
        config,
        auth,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Test = Result<(), Box<dyn std::error::Error>>;

    fn arguments() -> Vec<OsString> {
        let generation = ContentDigest::sha256(b"immutable camera generation").to_text();
        let mut args = vec![OsString::from("capture-rtp")];
        for (key, value) in [
            ("--root", "/tmp/fss-native-plan-no-io"),
            ("--site", "site:metadata-plan"),
            ("--sensor", "sensor:door"),
            ("--device-generation", generation.as_str()),
            ("--profile-generation", generation.as_str()),
            ("--profile", "metadata"),
            ("--peer", "127.0.0.1:554"),
            ("--authority", "camera.local"),
            ("--url", "rtsp://camera.local/live/"),
            ("--control-root", "rtsp://camera.local/live"),
            ("--media-index", "1"),
            ("--ingress", "340282366920938463463374607431768211455"),
            ("--stream-generation", "7"),
            ("--ssrc", "19"),
            ("--payload-type", "107"),
            ("--receive-origin-ns", "1700000000000000000"),
            ("--owner-authorized", "yes"),
            ("--plaintext", "yes"),
            ("--retain-source", "yes"),
        ] {
            args.push(OsString::from(key));
            args.push(OsString::from(value));
        }
        args
    }

    fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
        if let Some(index) = args.iter().position(|arg| arg == key) {
            args[index + 1] = OsString::from(value);
        } else {
            args.push(OsString::from(key));
            args.push(OsString::from(value));
        }
    }

    #[test]
    fn explicit_plan_preserves_full_stream_identity_and_independent_bounds() -> Test {
        let plan = parse(&arguments())?.ok_or("missing plan")?;
        assert_eq!(plan.tcp.key().ingress, u128::MAX);
        assert_eq!(plan.tcp.key(), plan.config.stream);
        assert_eq!(plan.payload_type, 107);
        assert_eq!(plan.protocol.channels, (0, 1));
        assert_eq!(plan.protocol.media_index, 1);
        assert_eq!(plan.capture_ns, 5_000_000_000);
        assert_eq!(plan.timeout_ns, 30_000_000_000);
        assert_eq!(plan.max_documents, 16);
        assert_eq!(plan.max_source_bytes, 1024 * 1024);
        assert_eq!(plan.max_records, 4096);
        assert_eq!(
            plan.binding.receive_interval.earliest.0,
            plan.receive_origin_ns
        );
        assert_eq!(
            plan.binding.receive_interval.latest.0,
            plan.receive_origin_ns
        );
        assert!(plan.auth.is_none());
        Ok(())
    }

    #[test]
    fn every_owner_approval_is_required_exactly() -> Test {
        for key in ["--owner-authorized", "--plaintext", "--retain-source"] {
            let mut args = arguments();
            set(&mut args, key, "no");
            assert!(parse(&args).is_err());
            let index = args
                .iter()
                .position(|arg| arg == key)
                .ok_or("missing fixture flag")?;
            drop(args.drain(index..index + 2));
            assert!(parse(&args).is_err());
        }
        Ok(())
    }

    #[test]
    fn peers_credentials_and_control_scope_cannot_silently_broaden() {
        for (key, value) in [
            ("--peer", "camera.local:554"),
            ("--peer", "0.0.0.0:554"),
            ("--peer", "239.0.0.1:554"),
            ("--peer", "127.0.0.1:0"),
            ("--authority", "other.local"),
            ("--url", "rtsp://user:password@camera.local/live/"),
            ("--url", "rtsp://camera.local/other/"),
            ("--url", "rtsp://camera.local/live/%2e%2e/private"),
            ("--control-root", "rtsp://other.local/live"),
            ("--control-root", "rtsp://camera.local/live?scope=all"),
            ("--root", "relative/root"),
            ("--root", "/tmp/../private"),
            ("--include-values", "yes"),
        ] {
            let mut args = arguments();
            set(&mut args, key, value);
            assert!(parse(&args).is_err(), "accepted invalid {key}");
        }
    }

    #[test]
    fn source_packet_document_deadline_and_channel_bounds_are_enforced() {
        for (key, value) in [
            ("--capture-ms", "0"),
            ("--capture-ms", "45001"),
            ("--timeout-ms", "9999"),
            ("--timeout-ms", "60001"),
            ("--max-documents", "0"),
            ("--max-documents", "65"),
            ("--max-source-bytes", "1"),
            ("--max-source-bytes", "8388609"),
            ("--max-records", "16385"),
            ("--max-document-bytes", "262145"),
            ("--max-fragments", "4097"),
            ("--document-timeout-ms", "60001"),
            ("--reorder-delay-ms", "0"),
            ("--payload-type", "95"),
            ("--payload-type", "128"),
            ("--rtp-channel", "255"),
            ("--media-index", "64"),
            ("--ingress", "0"),
            ("--stream-generation", "0"),
            ("--ssrc", "4294967296"),
            ("--receive-origin-ns", "-1"),
            (
                "--receive-origin-ns",
                "170141183460469231731687303715884105727",
            ),
        ] {
            let mut args = arguments();
            set(&mut args, key, value);
            assert!(parse(&args).is_err(), "accepted invalid {key}");
        }
    }

    #[test]
    fn every_supported_option_fits_the_argument_bound_at_its_valid_limit() -> Test {
        let mut args = arguments();
        for (key, value) in [
            ("--principal", "operator:explicit"),
            ("--capture-ms", "45000"),
            ("--timeout-ms", "60000"),
            ("--max-documents", "64"),
            ("--max-source-bytes", "8388608"),
            ("--max-records", "16384"),
            ("--rtp-channel", "254"),
            ("--max-document-bytes", "262144"),
            ("--max-fragments", "4096"),
            ("--document-timeout-ms", "60000"),
            ("--reorder-delay-ms", "60000"),
            ("--credential-file", "/private/not-read-by-parser"),
            ("--auth-realm", "camera"),
            ("--legacy-md5", "yes"),
            ("--legacy-no-qop", "yes"),
        ] {
            set(&mut args, key, value);
        }
        assert_eq!(args.len(), 69);
        let plan = parse(&args)?.ok_or("missing plan")?;
        assert_eq!(plan.protocol.channels, (254, 255));
        assert_eq!(plan.max_source_bytes, MAX_SOURCE_BYTES);
        assert_eq!(plan.max_records, MAX_RECORDS);
        assert_eq!(plan.max_documents, 64);
        assert!(plan.auth.is_some());
        Ok(())
    }

    #[test]
    fn digest_requires_an_exact_private_file_realm_and_explicit_legacy_policy() -> Test {
        let mut args = arguments();
        set(
            &mut args,
            "--credential-file",
            "/private/not-read-by-parser",
        );
        assert!(parse(&args).is_err());
        set(&mut args, "--auth-realm", "exact camera realm");
        let strict = parse(&args)?.ok_or("missing plan")?;
        let auth = strict.auth.ok_or("missing authentication")?;
        assert!(!auth.policy.allow_legacy_md5);
        assert!(!auth.policy.allow_legacy_no_qop);
        set(&mut args, "--legacy-no-qop", "yes");
        assert!(parse(&args).is_err());
        set(&mut args, "--legacy-md5", "yes");
        let legacy = parse(&args)?.ok_or("missing plan")?;
        assert_ne!(strict.approval, legacy.approval);
        assert!(
            legacy
                .auth
                .ok_or("missing authentication")?
                .policy
                .allow_legacy_no_qop
        );
        set(&mut args, "--credential-file", "relative-credential");
        assert!(parse(&args).is_err());
        Ok(())
    }

    #[test]
    fn approval_is_argument_order_independent_and_pins_owner_limits() -> Test {
        let args = arguments();
        let first = parse(&args)?.ok_or("missing plan")?;
        let mut reordered = vec![args[0].clone()];
        for pair in args[1..].chunks_exact(2).rev() {
            reordered.extend_from_slice(pair);
        }
        assert_eq!(
            first.approval,
            parse(&reordered)?.ok_or("missing plan")?.approval
        );
        for (key, value) in [
            ("--max-documents", "17"),
            ("--rtp-channel", "4"),
            ("--receive-origin-ns", "1700000000000000001"),
            ("--principal", "operator:another"),
            ("--payload-type", "108"),
        ] {
            let mut changed = args.clone();
            set(&mut changed, key, value);
            assert_ne!(
                first.approval,
                parse(&changed)?.ok_or("missing plan")?.approval
            );
        }
        Ok(())
    }

    #[test]
    fn help_and_malformed_argument_lists_do_no_work() {
        for args in [
            vec![OsString::from("capture-rtp")],
            vec![OsString::from("capture-rtp"), OsString::from("--help")],
            vec![OsString::from("capture-rtp"), OsString::from("-h")],
        ] {
            assert!(matches!(parse(&args), Ok(None)));
        }
        assert!(parse(&[]).is_err());
        let mut args = arguments();
        args.push(OsString::from("--site"));
        assert!(parse(&args).is_err());
        args.push(OsString::from("site:duplicate"));
        assert!(parse(&args).is_err());
        args[0] = OsString::from("import-rtp");
        assert!(parse(&args).is_err());
    }
}
