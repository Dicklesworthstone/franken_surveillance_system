#![forbid(unsafe_code)]
//! Actual operator processes against bounded read-only recorder SOAP fixtures.

use super::*;
use fss_cli::onvif_replay_plan::ReplayHandoff;

const TOKEN: &str = "PRIVATE_RECORDING_TOKEN_CANARY";
const SOURCE: &str = "PRIVATE_RECORDING_SOURCE_CANARY";
const START: &str = "20261101T120000Z";
const END: &str = "20261101T120100Z";

fn recorder_envelope(body: &str) -> String {
    format!("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:d=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:r=\"http://www.onvif.org/ver10/recording/wsdl\" xmlns:q=\"http://www.onvif.org/ver10/search/wsdl\" xmlns:p=\"http://www.onvif.org/ver10/replay/wsdl\" xmlns:t=\"http://www.onvif.org/ver10/schema\"><s:Body>{body}</s:Body></s:Envelope>")
}

fn services(address: SocketAddr) -> String {
    let entries: String = ["recording", "search", "replay"].into_iter().map(|kind| {
        format!("<d:Service><d:Namespace>http://www.onvif.org/ver10/{kind}/wsdl</d:Namespace><d:XAddr>http://{address}/onvif/{kind}_service</d:XAddr><d:Version><t:Major>2</t:Major><t:Minor>0</t:Minor></d:Version></d:Service>")
    }).collect();
    recorder_envelope(&format!("<d:GetServicesResponse>{entries}</d:GetServicesResponse>"))
}

fn source() -> String {
    format!("<t:Source><t:SourceId>urn:private:{SOURCE}</t:SourceId><t:Name>{SOURCE}</t:Name><t:Location>owner-site</t:Location><t:Description>Private recorder source</t:Description><t:Address>rtsp://untrusted-source.invalid/private</t:Address></t:Source>")
}

fn inventory() -> String {
    recorder_envelope(&format!("<r:GetRecordingsResponse><r:RecordingItem><t:RecordingToken>{TOKEN}</t:RecordingToken><t:Configuration>{}<t:Content>Private recording</t:Content><t:MaximumRetentionTime>PT86400S</t:MaximumRetentionTime></t:Configuration><t:Tracks><t:Track><t:TrackToken>video-0</t:TrackToken><t:Configuration><t:TrackType>Video</t:TrackType><t:Description>video</t:Description></t:Configuration></t:Track><t:Track><t:TrackToken>audio-0</t:TrackToken><t:Configuration><t:TrackType>Audio</t:TrackType><t:Description>audio</t:Description></t:Configuration></t:Track></t:Tracks></r:RecordingItem></r:GetRecordingsResponse>", source()))
}

fn information(known_bounds: bool) -> String {
    let recording_bounds = if known_bounds { "<t:EarliestRecording>2026-11-01T11:00:00Z</t:EarliestRecording><t:LatestRecording>2026-11-01T13:00:00Z</t:LatestRecording>" } else { "" };
    let track_bounds = if known_bounds { "<t:DataFrom>2026-11-01T11:00:00Z</t:DataFrom><t:DataTo>2026-11-01T13:00:00Z</t:DataTo>" } else { "" };
    recorder_envelope(&format!("<q:GetRecordingInformationResponse><q:RecordingInformation><t:RecordingToken>{TOKEN}</t:RecordingToken>{}<t:Content>Private recording</t:Content>{recording_bounds}<t:Track><t:TrackToken>video-0</t:TrackToken><t:TrackType>Video</t:TrackType><t:Description>video</t:Description>{track_bounds}</t:Track><t:RecordingStatus>Stopped</t:RecordingStatus></q:RecordingInformation></q:GetRecordingInformationResponse>", source()))
}

fn replay_uri(address: SocketAddr) -> String {
    recorder_envelope(&format!("<p:GetReplayUriResponse><p:Uri>rtsp://{address}/camera?cap={QUERY}</p:Uri></p:GetReplayUriResponse>"))
}

fn options(directory: &Directory, http: SocketAddr, rtsp: Option<SocketAddr>, authenticated: bool) -> Test<Vec<OsString>> {
    let mut args = vec![OsString::from(if rtsp.is_some() { "replay" } else { "recordings" })];
    args.extend(onvif_args(directory, http, None, authenticated)?);
    if let Some(rtsp) = rtsp {
        args.extend([
            "--recording-token".into(), TOKEN.into(), "--codec".into(), "avc".into(),
            "--replay-start".into(), START.into(), "--replay-end".into(), END.into(),
            "--rtsp-peer".into(), rtsp.to_string().into(),
            "--rtsp-authority".into(), rtsp.to_string().into(),
        ]);
    }
    Ok(args)
}

fn private_output(output: &Output) {
    secret_free(output);
    for value in [TOKEN, SOURCE, "Private recording", "untrusted-source.invalid"] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(value));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(value));
    }
}

type Exchange = (&'static str, &'static str, String);

fn serve(http: TcpListener, responses: Vec<Exchange>, authenticated: bool) -> Test<usize> {
    let count = responses.len();
    let mut nonces = BTreeSet::new();
    for (index, (target, operation, response)) in responses.into_iter().enumerate() {
        let mut peer = accept(&http)?;
        let request = http_request(&mut peer)?;
        assert_eq!(request.target, target);
        assert!(request.body.contains(operation));
        assert!(!request.body.contains("GetStreamUri") && !request.body.contains("FindRecordings"));
        assert!(request.authorization.is_none());
        if matches!(operation, "GetRecordingInformation" | "GetReplayUri") {
            assert!(request.body.contains(TOKEN));
        }
        if authenticated {
            let nonce = format!("{NONCE}-recording-{index}");
            peer.write_all(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{REALM}\",nonce=\"{nonce}\",algorithm=SHA-256,qop=\"auth\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())?;
            drop(peer);
            peer = accept(&http)?;
            let retry = http_request(&mut peer)?;
            assert_eq!(retry.target, request.target);
            assert_eq!(retry.body, request.body);
            assert!(nonces.insert(signed(&retry, &nonce)?));
        }
        soap_reply(&mut peer, &response)?;
    }
    no_connection(&http)?;
    Ok(count * if authenticated { 2 } else { 1 })
}

fn execute(http: TcpListener, responses: Vec<Exchange>, args: &[OsString], authenticated: bool) -> Test<Output> {
    thread::scope(|scope| -> Test<Output> {
        let expected = responses.len() * if authenticated { 2 } else { 1 };
        let server = scope.spawn(move || serve(http, responses, authenticated));
        let output = run("onvif", args)?;
        assert_eq!(server.join().map_err(|_| "recording SOAP fixture panicked")??, expected);
        private_output(&output);
        Ok(output)
    })
}

#[test]
fn recorder_discovery_preview_and_wrong_approval_have_no_effects() -> Test {
    let directory = Directory::new("recording-pure")?;
    let http = listener()?;
    let rtsp = listener()?;
    let mut args = options(&directory, http.local_addr()?, Some(rtsp.local_addr()?), false)?;
    args.extend(["--credential-file".into(), directory.0.join("absent-secret").into_os_string(), "--auth-realm".into(), REALM.into()]);
    let preview = run("onvif", &args)?;
    private_output(&preview);
    let preview = parse(&good(preview)?)?;
    assert!(!boolean(&preview, "device_contacted")?);
    assert!(!boolean(&preview, "credentials_read")?);
    args.extend(["--approve".into(), digest("wrong recorder approval").into()]);
    let refused = run("onvif", &args)?;
    assert!(!refused.status.success());
    private_output(&refused);
    no_connection(&http)?;
    no_connection(&rtsp)?;
    assert!(!directory.0.join("onvif.json").exists());
    Ok(())
}

#[test]
fn recorder_inventory_is_private_complete_and_never_starts_playback() -> Test {
    for authenticated in [false, true] {
        let directory = Directory::new("recording-inventory")?;
        let http = listener()?;
        let fence = http.try_clone()?;
        let rtsp = listener()?;
        let address = http.local_addr()?;
        let args = approved_onvif(&options(&directory, address, None, authenticated)?)?;
        let output = execute(http, vec![
            ("/onvif/device_service", "GetServices", services(address)),
            ("/onvif/recording_service", "GetRecordings", inventory()),
        ], &args, authenticated)?;
        let result = parse(&good(output)?)?;
        assert_eq!(integer(&result, "recordings")?, 1);
        assert_eq!(integer(&result, "tracks")?, 2);
        assert!(!boolean(&result, "handoff_ready")?);
        let path = directory.0.join("onvif.json");
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        let bytes = fs::read(&path)?;
        assert_eq!(ContentDigest::sha256(&bytes).to_text(), text(&result, "output_digest")?);
        let private = std::str::from_utf8(&bytes)?;
        assert!(private.contains(TOKEN) && private.contains(SOURCE));
        let parsed = parse(private)?;
        assert_eq!(text(&parsed, "schema")?, "fss.onvif_recording_inventory.v1");
        assert!(!boolean(&parsed, "source_evidence")?);
        assert!(!boolean(&parsed, "continuous_coverage_verified")?);
        assert!(ReplayHandoff::parse(&bytes).is_err());
        no_connection(&rtsp)?;
        let repeated = run("onvif", &args)?;
        assert!(!repeated.status.success());
        private_output(&repeated);
        no_connection(&fence)?;
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[test]
fn selected_recording_creates_exact_private_avc_or_hevc_handoff_without_capture() -> Test {
    for (codec, known) in [("avc", true), ("hevc", false)] {
        let directory = Directory::new("recording-selected")?;
        let http = listener()?;
        let rtsp = listener()?;
        let address = http.local_addr()?;
        let mut args = options(&directory, address, Some(rtsp.local_addr()?), true)?;
        let codec_index = args.iter().position(|arg| arg == "--codec").ok_or("missing codec")?;
        args[codec_index + 1] = codec.into();
        let args = approved_onvif(&args)?;
        let output = execute(http, vec![
            ("/onvif/device_service", "GetServices", services(address)),
            ("/onvif/search_service", "GetRecordingInformation", information(known)),
            ("/onvif/replay_service", "GetReplayUri", replay_uri(rtsp.local_addr()?)),
        ], &args, true)?;
        let result = parse(&good(output)?)?;
        assert_eq!(integer(&result, "http_exchanges")?, 6);
        assert!(boolean(&result, "handoff_ready")?);
        assert!(!boolean(&result, "capture_authorized")?);
        let path = directory.0.join("onvif.json");
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        let bytes = fs::read(&path)?;
        assert_eq!(ContentDigest::sha256(&bytes).to_text(), text(&result, "output_digest")?);
        let handoff = ReplayHandoff::parse(&bytes)?;
        assert_eq!(handoff.codec().as_str(), codec);
        assert_eq!(handoff.window().to_string(), format!("clock={START}-{END}"));
        assert_eq!(handoff.recording_token_digest(), ContentDigest::sha256(TOKEN.as_bytes()));
        assert_eq!(handoff.range_assessment()?, if known { "within_advertised_bounds" } else { "unknown" });
        assert_eq!(handoff.render()?.as_bytes(), bytes);
        let private = parse(std::str::from_utf8(&bytes)?)?;
        assert_eq!(text(&private, "uri_lifetime_basis")?, "unknown");
        assert!(!boolean(&private, "source_evidence")?);
        no_connection(&rtsp)?;
    }
    Ok(())
}

#[test]
fn recording_selection_refuses_missing_video_and_known_range_violations_before_uri() -> Test {
    let cases = [
        (information(true).replace("<t:TrackType>Video</t:TrackType>", "<t:TrackType>Audio</t:TrackType>"), "ERR-ONVIF-RECORDING-VIDEO-001"),
        (information(false).replace("<t:Content>", "<t:LatestRecording>2026-11-01T12:00:30Z</t:LatestRecording><t:Content>"), "ERR-ONVIF-RECORDING-RANGE-001"),
        (information(true).replace("<t:RecordingStatus>Stopped</t:RecordingStatus>", "<t:RecordingStatus>Removed</t:RecordingStatus>"), "ERR-ONVIF-RECORDING-STATE-001"),
    ];
    for (information, expected) in cases {
        let directory = Directory::new("recording-refused")?;
        let http = listener()?;
        let rtsp = listener()?;
        let address = http.local_addr()?;
        let args = approved_onvif(&options(&directory, address, Some(rtsp.local_addr()?), false)?)?;
        let refused = execute(http, vec![
            ("/onvif/device_service", "GetServices", services(address)),
            ("/onvif/search_service", "GetRecordingInformation", information),
        ], &args, false)?;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains(expected));
        assert!(!directory.0.join("onvif.json").exists());
        no_connection(&rtsp)?;
    }
    Ok(())
}

#[test]
fn foreign_recording_service_and_replay_uri_never_expand_owner_scope() -> Test {
    for foreign_service in [true, false] {
        let directory = Directory::new("recording-foreign")?;
        let http = listener()?;
        let rtsp = listener()?;
        let foreign = listener()?;
        let address = http.local_addr()?;
        let args = approved_onvif(&options(&directory, address, Some(rtsp.local_addr()?), true)?)?;
        let responses = if foreign_service {
            vec![("/onvif/device_service", "GetServices", services(foreign.local_addr()?))]
        } else {
            vec![
                ("/onvif/device_service", "GetServices", services(address)),
                ("/onvif/search_service", "GetRecordingInformation", information(true)),
                ("/onvif/replay_service", "GetReplayUri", replay_uri(foreign.local_addr()?)),
            ]
        };
        let refused = execute(http, responses, &args, true)?;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-ONVIF-SCOPE-001"));
        assert!(!directory.0.join("onvif.json").exists());
        no_connection(&rtsp)?;
        no_connection(&foreign)?;
    }
    Ok(())
}
