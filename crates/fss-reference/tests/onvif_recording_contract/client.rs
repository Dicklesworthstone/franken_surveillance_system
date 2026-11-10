#![forbid(unsafe_code)]
//! Real native HTTP loopbacks with a bounded fixture authority and synthetic credentials.

use super::fixtures::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fss_core::ContentDigest;
use fss_reference::onvif::authentication::{UsernameToken, UtcDateTime};
use fss_reference::onvif::client::{
    AuthenticationConfig, ClientConfig, ClientError, DigestConfig, OnvifContext, RtspScope,
};
use fss_reference::onvif::client::recording::{inventory, select};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpLimits, HttpOperation, HttpRoute};
use fss_reference::onvif::wire::{
    self, MediaVersion, RecordingCheckError as Check, RecordingRangeAssessment as Assessment,
    SoapFaultSubcode, SoapRequest, WireError,
};
use fss_reference::rtsp::authentication::{
    DigestAuthorization, DigestChallenge, DigestCredentials, DigestPolicy,
};
use fss_reference::rtsp::client::replay::ReplayWindow;

type Test = Result<(), Box<dyn std::error::Error>>;
const REALM: &str = "fixture-recording-owner";

struct Server {
    peer: SocketAddr,
    stopped: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<JoinHandle<()>>,
}
impl Server {
    fn start(replies: impl FnOnce(SocketAddr) -> Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture bind");
        listener.set_nonblocking(true).unwrap();
        let peer = listener.local_addr().unwrap();
        let replies = replies(peer);
        let stopped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::clone(&stopped);
        let captured = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            let started = Instant::now();
            for reply in replies {
                let mut stream = loop {
                    if stop.load(Ordering::SeqCst) || started.elapsed() > Duration::from_secs(5) { return; }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => panic!("fixture accept"),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut chunk).expect("fixture request");
                    assert!(count > 0, "complete request before EOF");
                    bytes.extend_from_slice(&chunk[..count]);
                    assert!(bytes.len() <= 32_768);
                    if let Some(head) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..head]).unwrap();
                        let length: usize = headers.lines().find_map(|line| {
                            line.strip_prefix("Content-Length: ").map(|value| value.parse().unwrap())
                        }).unwrap();
                        if bytes.len() == head + 4 + length { break; }
                    }
                }
                captured.lock().unwrap().push(String::from_utf8(bytes).unwrap());
                // Exercise the production framing owner across both header and XML boundaries.
                for chunk in reply.as_bytes().chunks(29) {
                    if stream.write_all(chunk).is_err() { break; }
                }
            }
        });
        Self { peer, stopped, requests, worker: Some(worker) }
    }
    fn requests(&self) -> Vec<String> { self.requests.lock().unwrap().clone() }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() { worker.join().unwrap(); }
    }
}

struct Owner {
    peer: SocketAddr,
    started: Instant,
    cancelled: AtomicBool,
    digest_calls: AtomicU32,
    token_calls: AtomicU32,
}
impl Owner {
    fn new(peer: SocketAddr) -> Self {
        Self { peer, started: Instant::now(), cancelled: AtomicBool::new(false),
            digest_calls: AtomicU32::new(0), token_calls: AtomicU32::new(0) }
    }
    fn now(&self) -> u64 { self.started.elapsed().as_nanos() as u64 + 1 }
}
impl HttpAuthority for Owner {
    fn checkpoint(&self, route: &HttpRoute, _: HttpOperation, _: u64, deadline: u64) -> Result<(), HttpDenial> {
        if self.cancelled.load(Ordering::SeqCst) { return Err(HttpDenial::Cancelled); }
        if self.now() >= deadline { return Err(HttpDenial::Deadline); }
        if route.peer() != self.peer || route.authority() != self.peer.to_string()
            || route.generation() != 1
            || !matches!(route.target(), "/onvif/device_service" | "/onvif/recording_service"
                | "/onvif/search_service" | "/onvif/replay_service") {
            return Err(HttpDenial::Unauthorized);
        }
        Ok(())
    }
}
impl OnvifContext for Owner {
    fn now_ns(&self) -> Result<u64, ClientError> {
        if self.cancelled.load(Ordering::SeqCst) { return Err(ClientError::Cancelled); }
        Ok(self.now())
    }
    fn wait(&self, deadline: u64) -> Result<(), ClientError> {
        if self.now_ns()? >= deadline { return Err(ClientError::Deadline); }
        thread::sleep(Duration::from_millis(1));
        if self.now_ns()? >= deadline { return Err(ClientError::Deadline); }
        Ok(())
    }
    fn authorize(&self, route: &HttpRoute, challenge: &DigestChallenge) -> Result<DigestAuthorization, ClientError> {
        self.checkpoint(route, HttpOperation::Write, self.now(), 4_000_000_000)
            .map_err(|_| ClientError::Authority)?;
        let n = self.digest_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let credentials = DigestCredentials::new("fixture-user", "fixture-password")?;
        Ok(challenge.authorize("POST", route.target(), &credentials, [n as u8; 16], 1)?)
    }
    fn username_token(&self, route: &HttpRoute, request: &SoapRequest, created: UtcDateTime) -> Result<UsernameToken, ClientError> {
        self.checkpoint(route, HttpOperation::Write, self.now(), 4_000_000_000)
            .map_err(|_| ClientError::Authority)?;
        let expected = match route.target() {
            "/onvif/device_service" => wire::get_services_request(),
            "/onvif/recording_service" => wire::get_recordings_request(),
            "/onvif/search_service" => wire::get_recording_information_request(TOKEN)?,
            "/onvif/replay_service" => wire::get_replay_uri_request(TOKEN)?,
            _ => return Err(ClientError::Authority),
        };
        if request.action() != expected.action() || request.body() != expected.body() || request.has_username_token() {
            return Err(ClientError::Authority);
        }
        let n = self.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let credentials = DigestCredentials::new("fixture-user", "fixture-password")?;
        Ok(UsernameToken::new(&credentials, [n as u8; 16], created))
    }
}

fn config(peer: SocketAddr) -> ClientConfig {
    ClientConfig {
        media_version: MediaVersion::Media1,
        device: HttpRoute::new(peer, &peer.to_string(), "/onvif/device_service", 1,
            ContentDigest::sha256(b"fixture-explicit-plaintext-consent")).unwrap(),
        service_root: "/onvif".into(),
        auth: None,
        rtsp: Some(RtspScope { peer: "127.0.0.1:554".parse().unwrap(), authority: "127.0.0.1:554".into() }),
        limits: HttpLimits::default(),
        deadline_ns: 4_000_000_000,
        max_steps: 10000,
    }
}
fn digest_config(peer: SocketAddr) -> ClientConfig {
    let mut config = config(peer);
    config.auth = Some(AuthenticationConfig::HttpDigest(DigestConfig {
        expected_realm: REALM.into(), policy: DigestPolicy::default(),
    }));
    config
}
fn window() -> ReplayWindow {
    ReplayWindow::from_timestamps("20261101T120010Z", "20261101T120020Z").unwrap()
}
fn response(status: u16, body: String) -> String {
    format!("HTTP/1.1 {status} fixture\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}
fn ok(body: String) -> String { response(200, body) }
fn challenge(realm: &str) -> String {
    format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{realm}\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n")
}

#[test]
fn native_inventory_reads_recording_service_and_never_requests_replay_or_search() -> Test {
    let server = Server::start(|peer| vec![ok(services(&peer.to_string())),
        ok(recordings(&recording_item(TOKEN, &configured_track(TRACK, "Video"))))]);
    let owner = Owner::new(server.peer);
    let mut config = config(server.peer);
    config.media_version = MediaVersion::Media2;
    config.rtsp = None;
    let result = inventory(&config, &owner)?;
    assert_eq!(result.exchanges, 2);
    assert_eq!(result.recordings[0].token, TOKEN);
    assert_eq!(result.recordings[0].tracks[0].token, TRACK);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /onvif/device_service HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("POST /onvif/recording_service HTTP/1.1\r\n"));
    assert!(requests[1].contains("<trc:GetRecordings/>"));
    assert!(requests.iter().all(|request| !request.contains("FindRecordings") && !request.contains("GetReplayUri")));
    assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_selection_authenticates_each_exact_service_and_binds_all_original_response_digests() -> Test {
    let server = Server::start(|peer| vec![
        challenge(REALM), ok(services(&peer.to_string())),
        challenge(REALM), ok(info()),
        challenge(REALM), ok(replay_uri(URI)),
    ]);
    let owner = Owner::new(server.peer);
    let result = select(&digest_config(server.peer), TOKEN, window(), &owner)?;
    assert_eq!(result.exchanges, 6);
    assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 3);
    assert_eq!(result.information.token, TOKEN);
    assert_eq!(result.information.video_track()?.token, TRACK);
    assert_eq!(result.information.validate_requested_window(window())?, Assessment::WithinAdvertisedBounds);
    assert_eq!(result.uri, URI);
    assert_eq!(result.peer, "127.0.0.1:554".parse::<SocketAddr>()?);
    assert_eq!(result.authority, "127.0.0.1:554");
    assert_eq!(result.services.response_body_digest, ContentDigest::sha256(services(&server.peer.to_string()).as_bytes()));
    assert_eq!(result.information.response_body_digest, ContentDigest::sha256(info().as_bytes()));
    assert_eq!(result.uri_response_digest, ContentDigest::sha256(replay_uri(URI).as_bytes()));
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    for (pair, route) in requests.chunks_exact(2).zip(["/onvif/device_service", "/onvif/search_service", "/onvif/replay_service"]) {
        assert!(pair[0].starts_with(&format!("POST {route} HTTP/1.1\r\n")));
        assert!(!pair[0].contains("Authorization:"));
        assert!(pair[1].contains("Authorization: Digest "));
        assert!(pair[1].contains(&format!("uri=\"{route}\"")));
        assert!(pair[1].contains("nc=00000001"));
    }
    assert!(requests[3].contains("<tse:RecordingToken>private-recording-1</tse:RecordingToken>"));
    assert!(requests[5].contains("<trp:RecordingToken>private-recording-1</trp:RecordingToken>"));
    assert!(requests.iter().all(|r| !r.contains("GetProfiles") && !r.contains("GetRecordings") && !r.contains("FindRecordings")));
    let debug = format!("{result:?}");
    assert!(!debug.contains(TOKEN) && !debug.contains(URI));
    Ok(())
}

#[test]
fn unknown_advertised_dates_remain_unknown_without_changing_the_requested_window() -> Test {
    let body = information(TOKEN, &track(TRACK, "Video", None, None), "", "Stopped", "");
    let server = Server::start(|peer| vec![ok(services(&peer.to_string())), ok(body), ok(replay_uri(URI))]);
    let owner = Owner::new(server.peer);
    let requested = window();
    let result = select(&config(server.peer), TOKEN, requested, &owner)?;
    assert_eq!(result.information.validate_requested_window(requested)?, Assessment::Unknown);
    assert_eq!(result.information.video_track()?.range.earliest_ns, None);
    assert_eq!(requested, window());
    assert_eq!(server.requests().len(), 3);
    Ok(())
}

#[test]
fn mismatched_ambiguous_contradictory_or_outside_selection_stops_before_uri_acquisition() {
    let cases = [
        (info().replace(TOKEN, "different-recording"), Check::TokenMismatch),
        (information(TOKEN, &format!("{}{}", track("one", "Video", Some(START), Some(END)), track("two", "Video", Some(START), Some(END))), "", "Stopped", ""), Check::AmbiguousVideoTracks),
        (information(TOKEN, &track("audio", "Audio", None, None), "", "Stopped", ""), Check::NoVideoTrack),
        (information(TOKEN, &track(TRACK, "Video", Some(END), Some(START)), &overall(Some(START), Some(END)), "Stopped", ""), Check::ContradictoryAdvertisedBounds),
        (information(TOKEN, &track(TRACK, "Video", Some("2026-11-01T12:00:15Z"), Some(END)), &overall(Some(START), Some(END)), "Stopped", ""), Check::OutsideAdvertisedBounds),
        (information(TOKEN, &track(TRACK, "Video", Some(START), Some(END)), &overall(Some(START), Some(END)), "Removed", ""), Check::RecordingUnavailable),
    ];
    for (body, expected) in cases {
        let server = Server::start(|peer| vec![ok(services(&peer.to_string())), ok(body)]);
        let owner = Owner::new(server.peer);
        assert!(matches!(select(&config(server.peer), TOKEN, window(), &owner), Err(ClientError::Recording(error)) if error == expected));
        assert_eq!(server.requests().len(), 2);
        assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn both_selected_service_routes_are_scoped_before_followup_or_new_credentials() {
    for target in ["search", "replay"] {
        for invalid in ["http://foreign.invalid/onvif/service", "http://127.0.0.1:9/onvif/service", "https://127.0.0.1/onvif/service", "outside"] {
            let server = Server::start(|peer| {
                let advertised = services(&peer.to_string());
                let valid = format!("http://{peer}/onvif/{target}_service");
                let invalid = if invalid == "outside" { format!("http://{peer}/outside/service") } else { invalid.into() };
                vec![challenge(REALM), ok(advertised.replace(&valid, &invalid))]
            });
            let owner = Owner::new(server.peer);
            assert!(matches!(select(&digest_config(server.peer), TOKEN, window(), &owner), Err(ClientError::Scope)));
            assert_eq!(server.requests().len(), 2);
            assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn inventory_service_and_returned_rtsp_uri_cannot_expand_scope() {
    let server = Server::start(|peer| vec![ok(services(&peer.to_string()).replace(
        &format!("http://{peer}/onvif/recording_service"), "http://foreign.invalid/onvif/recording"))]);
    let owner = Owner::new(server.peer);
    assert!(matches!(inventory(&config(server.peer), &owner), Err(ClientError::Scope)));
    assert_eq!(server.requests().len(), 1);
    for uri in ["rtsp://foreign.invalid/recordings/1", "rtsp://user:password@127.0.0.1:554/recordings/1", "rtsps://127.0.0.1:554/recordings/1"] {
        let server = Server::start(|peer| vec![ok(services(&peer.to_string())), ok(info()), ok(replay_uri(uri))]);
        let owner = Owner::new(server.peer);
        assert!(matches!(select(&config(server.peer), TOKEN, window(), &owner), Err(ClientError::Scope)));
        assert_eq!(server.requests().len(), 3);
    }
}

#[test]
fn typed_recording_faults_survive_http_error_status_without_leaking_remote_prose() {
    for (at_replay, subcode) in [(false, SoapFaultSubcode::NoRecording), (true, SoapFaultSubcode::InvalidStreamSetup)] {
        let server = Server::start(|peer| {
            let mut replies = vec![ok(services(&peer.to_string()))];
            if at_replay { replies.push(ok(info())); }
            replies.push(response(500, fault(if at_replay { "InvalidStreamSetup" } else { "NoRecording" })));
            replies
        });
        let owner = Owner::new(server.peer);
        let error = select(&config(server.peer), TOKEN, window(), &owner).expect_err("remote fault");
        assert!(matches!(&error, ClientError::Wire(WireError::SoapFault(fault)) if fault.subcode == subcode));
        assert!(!format!("{error:?} {error}").contains("private-host-and-token"));
        assert_eq!(server.requests().len(), if at_replay { 3 } else { 2 });
    }
    let server = Server::start(|peer| vec![ok(services(&peer.to_string())), response(500, info())]);
    let owner = Owner::new(server.peer);
    assert!(matches!(select(&config(server.peer), TOKEN, window(), &owner), Err(ClientError::HttpStatus(500))));
}

#[test]
fn unsupported_service_and_authentication_refusal_do_not_fall_back_or_retry_forever() {
    let server = Server::start(|peer| vec![ok(service_response(&service("urn:unknown", &format!("http://{peer}/onvif/device_service"))))]);
    let owner = Owner::new(server.peer);
    assert!(matches!(select(&config(server.peer), TOKEN, window(), &owner), Err(ClientError::Unsupported)));
    assert_eq!(server.requests().len(), 1);
    let server = Server::start(|_| vec![challenge("wrong-realm")]);
    let owner = Owner::new(server.peer);
    assert!(select(&digest_config(server.peer), TOKEN, window(), &owner).is_err());
    assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 0);
    assert_eq!(server.requests().len(), 1);
    let server = Server::start(|_| vec![challenge(REALM), challenge(REALM)]);
    let owner = Owner::new(server.peer);
    assert!(matches!(select(&digest_config(server.peer), TOKEN, window(), &owner), Err(ClientError::AuthenticationRefused)));
    assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn malformed_request_missing_rtsp_approval_cancellation_and_work_budget_fail_before_io() {
    let server = Server::start(|_| Vec::new());
    let owner = Owner::new(server.peer);
    assert!(matches!(select(&config(server.peer), "", window(), &owner), Err(ClientError::Wire(WireError::InvalidField))));
    let mut scoped = config(server.peer);
    scoped.rtsp = None;
    assert!(matches!(select(&scoped, TOKEN, window(), &owner), Err(ClientError::Scope)));
    let mut bounded = config(server.peer);
    bounded.max_steps = 1;
    assert!(matches!(select(&bounded, TOKEN, window(), &owner), Err(ClientError::Budget)));
    owner.cancelled.store(true, Ordering::SeqCst);
    assert!(matches!(select(&config(server.peer), TOKEN, window(), &owner), Err(ClientError::Cancelled)));
    assert!(server.requests().is_empty());
    assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.token_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn username_token_flow_uses_unsigned_owned_clock_then_three_exact_fresh_requests() -> Test {
    let utc = soap("<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>Manual</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings><tt:TimeZone><tt:TZ>UTC</tt:TZ></tt:TimeZone><tt:UTCDateTime><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>0</tt:Minute><tt:Second>0</tt:Second></tt:Time><tt:Date><tt:Year>2026</tt:Year><tt:Month>11</tt:Month><tt:Day>1</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>");
    let server = Server::start(|peer| vec![ok(utc), ok(services(&peer.to_string())), ok(info()), ok(replay_uri(URI))]);
    let owner = Owner::new(server.peer);
    let mut config = config(server.peer);
    config.auth = Some(AuthenticationConfig::UsernameTokenDigest);
    let result = select(&config, TOKEN, window(), &owner)?;
    assert_eq!(result.exchanges, 4);
    assert_eq!(owner.token_calls.load(Ordering::SeqCst), 3);
    assert_eq!(owner.digest_calls.load(Ordering::SeqCst), 0);
    let requests = server.requests();
    assert!(requests[0].contains("GetSystemDateAndTime"));
    assert!(!requests[0].contains("UsernameToken"));
    for request in &requests[1..] {
        assert!(request.contains("UsernameToken"));
        assert!(request.contains("PasswordDigest"));
        assert!(!request.contains("fixture-password"));
        assert!(!request.contains("Authorization: Digest"));
    }
    assert_ne!(requests[1], requests[2]);
    assert_ne!(requests[2], requests[3]);
    Ok(())
}
