#![forbid(unsafe_code)]
//! Real native HTTP loopback fixtures for the owner-scoped ONVIF → RTSP handoff.
//! Fixture credentials and deterministic entropy below are never production credentials.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fss_core::ContentDigest;
use fss_reference::onvif::client::{
    AuthenticationConfig, ClientConfig, ClientError, DigestConfig, MediaDiscovery, OnvifContext,
    RtspScope, StreamValidity, run, validate_stream_uri,
};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpLimits, HttpOperation, HttpRoute};
use fss_reference::onvif::wire::{MediaVersion, ServiceVersion, VideoEncoding, WireError};
use fss_reference::rtsp::authentication::{
    DigestAuthorization, DigestChallenge, DigestCredentials, DigestPolicy,
};

#[path = "onvif_onboarding_contract/username_token.rs"]
mod username_token;

const REALM: &str = "fixture-camera";
const TOKEN: &str = "fixture-main";
const STREAM: &str = "rtsp://127.0.0.1:554/live/main?channel=1&token=fixture%3Dvalue";

struct Server {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    fn start(replies: impl FnOnce(SocketAddr) -> Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture bind");
        listener.set_nonblocking(true).unwrap();
        let peer = listener.local_addr().unwrap();
        let replies = replies(peer);
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::clone(&stop);
        let captured = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            let started = Instant::now();
            for reply in replies {
                let mut stream = loop {
                    if stopped.load(Ordering::SeqCst) || started.elapsed() > Duration::from_secs(5)
                    {
                        return;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => panic!("fixture accept"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut chunk).expect("fixture request read");
                    assert!(count > 0, "complete request before EOF");
                    request.extend_from_slice(&chunk[..count]);
                    assert!(request.len() <= 32768);
                    if let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..head]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("Content-Length: ")
                                    .map(|s| s.parse().unwrap())
                            })
                            .unwrap();
                        if request.len() == head + 4 + length {
                            break;
                        }
                    }
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                // Deliberately split header and SOAP bytes at non-token boundaries.
                for part in reply.as_bytes().chunks(31) {
                    if stream.write_all(part).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            peer,
            stop,
            requests,
            thread: Some(thread),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

struct Context {
    start: Instant,
    peer: SocketAddr,
    cancelled: AtomicBool,
    auth_calls: AtomicU32,
    boundaries: AtomicU32,
}

impl Context {
    fn new(peer: SocketAddr) -> Self {
        Self {
            start: Instant::now(),
            peer,
            cancelled: AtomicBool::new(false),
            auth_calls: AtomicU32::new(0),
            boundaries: AtomicU32::new(0),
        }
    }
    fn now(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64 + 1
    }
}

impl HttpAuthority for Context {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        _: HttpOperation,
        _: u64,
        deadline: u64,
    ) -> Result<(), HttpDenial> {
        self.boundaries.fetch_add(1, Ordering::SeqCst);
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(HttpDenial::Cancelled);
        }
        if self.now() >= deadline {
            return Err(HttpDenial::Deadline);
        }
        if route.peer() != self.peer
            || route.authority() != self.peer.to_string()
            || route.generation() != 1
            || !matches!(
                route.target(),
                "/onvif/device_service" | "/onvif/media_service" | "/onvif/media2_service"
            )
        {
            return Err(HttpDenial::Unauthorized);
        }
        Ok(())
    }
}

impl OnvifContext for Context {
    fn now_ns(&self) -> Result<u64, ClientError> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(ClientError::Cancelled);
        }
        Ok(self.now())
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        if self.now_ns()? >= deadline_ns {
            return Err(ClientError::Deadline);
        }
        thread::sleep(Duration::from_millis(1));
        if self.now_ns()? >= deadline_ns {
            return Err(ClientError::Deadline);
        }
        Ok(())
    }
    fn authorize(
        &self,
        route: &HttpRoute,
        challenge: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        let n = self.auth_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let credentials = DigestCredentials::new("fixture-user", "fixture-password")?;
        Ok(challenge.authorize("POST", route.target(), &credentials, [n as u8; 16], 1)?)
    }
}

fn config(peer: SocketAddr) -> ClientConfig {
    ClientConfig {
        media_version: MediaVersion::Media1,
        device: HttpRoute::new(
            peer,
            &peer.to_string(),
            "/onvif/device_service",
            1,
            ContentDigest::sha256(b"fixture-owner-plaintext-approval"),
        )
        .unwrap(),
        service_root: "/onvif".into(),
        auth: Some(AuthenticationConfig::HttpDigest(DigestConfig {
            expected_realm: REALM.into(),
            policy: DigestPolicy::default(),
        })),
        rtsp: Some(RtspScope {
            peer: "127.0.0.1:554".parse().unwrap(),
            authority: "127.0.0.1:554".into(),
        }),
        limits: HttpLimits::default(),
        deadline_ns: 4_000_000_000,
        max_steps: 10000,
    }
}

fn soap(body: &str) -> String {
    format!(
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body>{body}</s:Body></s:Envelope>"
    )
}
fn ok(body: String) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
fn capabilities(uri: &str) -> String {
    ok(soap(&format!(
        "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media><tt:XAddr>{uri}</tt:XAddr><tt:StreamingCapabilities><tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP></tt:StreamingCapabilities></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>"
    )))
}
fn profiles() -> String {
    ok(soap(&format!(
        "<trt:GetProfilesResponse><trt:Profiles token=\"{TOKEN}\"><tt:Name>Fixture Main</tt:Name><tt:VideoEncoderConfiguration token=\"encoder\"><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles></trt:GetProfilesResponse>"
    )))
}
fn stream(uri: &str) -> String {
    let uri = uri.replace('&', "&amp;");
    ok(soap(&format!(
        "<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{uri}</tt:Uri><tt:InvalidAfterConnect>false</tt:InvalidAfterConnect><tt:InvalidAfterReboot>false</tt:InvalidAfterReboot><tt:Timeout>PT0S</tt:Timeout></trt:MediaUri></trt:GetStreamUriResponse>"
    )))
}
fn challenge(realm: &str) -> String {
    format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{realm}\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
    )
}

#[test]
fn real_native_roundtrip_authenticates_each_exact_route_and_preserves_uri() {
    let server = Server::start(|peer| {
        vec![
            challenge(REALM),
            capabilities(&format!("http://{peer}/onvif/media_service")),
            challenge(REALM),
            profiles(),
            challenge(REALM),
            stream(STREAM),
        ]
    });
    let cx = Context::new(server.peer);
    let result = run(&config(server.peer), Some(TOKEN), &cx).unwrap();
    assert_eq!(result.exchanges, 6);
    assert_eq!(result.profiles.len(), 1);
    let selection = result.selection.as_ref().unwrap();
    assert_eq!(selection.stream.uri, STREAM);
    assert!(selection.stream.is_stable());
    assert_eq!(
        selection.profile.video.as_ref().unwrap().encoding,
        VideoEncoding::H264
    );
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 3);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    for (index, request) in requests.iter().enumerate() {
        let target = if index < 2 {
            "/onvif/device_service"
        } else {
            "/onvif/media_service"
        };
        assert!(request.starts_with(&format!("POST {target} HTTP/1.1\r\n")));
        assert_eq!(request.contains("Authorization: Digest "), index % 2 == 1);
        if index % 2 == 1 {
            assert!(request.contains(&format!("uri=\"{target}\"")));
        }
        assert!(!request.contains("fixture-password"));
    }
    assert!(requests[5].contains("<tt:Protocol>RTSP</tt:Protocol>"));
    let debug = format!("{result:?} {selection:?}");
    for private in [STREAM, TOKEN, "Fixture Main", REALM] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn inventory_is_read_only_and_does_not_request_a_stream() {
    let server = Server::start(|peer| {
        vec![
            capabilities(&format!("http://{peer}/onvif/media_service")),
            profiles(),
        ]
    });
    let result = run(&config(server.peer), None, &Context::new(server.peer)).unwrap();
    assert!(result.selection.is_none());
    assert_eq!(result.exchanges, 2);
    assert!(
        server
            .requests()
            .iter()
            .all(|s| !s.contains("GetStreamUri"))
    );
}

#[test]
fn advertised_service_cannot_expand_host_port_or_path_authority() {
    for variant in 0..5 {
        let server = Server::start(|peer| {
            let uri = match variant {
                0 => format!("http://127.0.0.2:{}/onvif/media_service", peer.port()),
                1 => format!("http://{peer}/onvif-other/media"),
                2 => format!("http://{peer}/onvif/../admin"),
                3 => format!("https://{peer}/onvif/media_service"),
                _ => format!("http://{peer}/onvif/%2e%2e/admin"),
            };
            vec![capabilities(&uri)]
        });
        let cx = Context::new(server.peer);
        assert!(matches!(
            run(&config(server.peer), None, &cx),
            Err(ClientError::Scope)
        ));
        assert_eq!(server.requests().len(), 1);
        assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn wrong_realm_never_reaches_credentials_and_failed_authentication_never_loops() {
    let server = Server::start(|_| vec![challenge("wrong-fixture-realm")]);
    let cx = Context::new(server.peer);
    assert!(matches!(
        run(&config(server.peer), None, &cx),
        Err(ClientError::Authentication(_))
    ));
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(server.requests().len(), 1);

    let server = Server::start(|_| vec![challenge(REALM), challenge(REALM)]);
    let cx = Context::new(server.peer);
    assert!(matches!(
        run(&config(server.peer), None, &cx),
        Err(ClientError::AuthenticationRefused)
    ));
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn no_credentials_is_explicit_and_unknown_profile_never_requests_a_uri() {
    let server = Server::start(|_| vec![challenge(REALM)]);
    let mut cfg = config(server.peer);
    cfg.auth = None;
    assert!(matches!(
        run(&cfg, None, &Context::new(server.peer)),
        Err(ClientError::AuthenticationRequired)
    ));
    let server = Server::start(|peer| {
        vec![
            capabilities(&format!("http://{peer}/onvif/media_service")),
            profiles(),
        ]
    });
    assert!(matches!(
        run(
            &config(server.peer),
            Some("different-profile"),
            &Context::new(server.peer)
        ),
        Err(ClientError::Profile)
    ));
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn returned_rtsp_uri_needs_independent_exact_authority() {
    let server = Server::start(|peer| {
        vec![
            capabilities(&format!("http://{peer}/onvif/media_service")),
            profiles(),
            stream("rtsp://127.0.0.2:554/live"),
        ]
    });
    assert!(matches!(
        run(
            &config(server.peer),
            Some(TOKEN),
            &Context::new(server.peer)
        ),
        Err(ClientError::Scope)
    ));
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn scope_and_cancellation_fail_before_network_or_secret_access() {
    let server = Server::start(|_| Vec::new());
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.service_root = "/other".into();
    assert!(matches!(run(&cfg, None, &cx), Err(ClientError::Scope)));
    assert_eq!(cx.boundaries.load(Ordering::SeqCst), 0);
    cfg.service_root = "/onvif".into();
    cx.cancelled.store(true, Ordering::SeqCst);
    assert!(matches!(run(&cfg, None, &cx), Err(ClientError::Cancelled)));
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
    assert!(server.requests().is_empty());
}

#[test]
fn soap_error_status_preserves_faults_without_accepting_a_success_body() {
    let fault = soap(
        "<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value xmlns:ter=\"http://www.onvif.org/ver10/error\">ter:NotAuthorized</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang=\"en\">private remote reason</s:Text></s:Reason></s:Fault>",
    );
    let server =
        Server::start(|_| vec![ok(fault).replacen("200 OK", "500 Internal Server Error", 1)]);
    let error = run(&config(server.peer), None, &Context::new(server.peer)).unwrap_err();
    assert!(matches!(error, ClientError::Wire(WireError::SoapFault(_))));
    assert!(!format!("{error:?}").contains("private remote reason"));

    let server = Server::start(|peer| {
        vec![
            capabilities(&format!("http://{peer}/onvif/media_service")).replacen(
                "200 OK",
                "500 Internal Server Error",
                1,
            ),
        ]
    });
    assert!(matches!(
        run(&config(server.peer), None, &Context::new(server.peer)),
        Err(ClientError::HttpStatus(500))
    ));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn stream_scope_accepts_safe_query_without_normalizing_private_tokens() {
    let scope = RtspScope {
        peer: "127.0.0.1:554".parse().unwrap(),
        authority: "127.0.0.1:554".into(),
    };
    validate_stream_uri(STREAM, &scope).unwrap();
    for uri in [
        "rtsp://user:password@127.0.0.1:554/live",
        "rtsp://127.0.0.1:555/live",
        "rtsp://127.0.0.1:554/live#fragment",
        "rtsp://127.0.0.1:554/live/%2e%2e/admin",
        "rtsp://127.0.0.1:554/live?x=%0d%0aAuthorization",
        "rtsp://127.0.0.1:554/live?x=%252e",
    ] {
        assert!(matches!(
            validate_stream_uri(uri, &scope),
            Err(ClientError::Scope)
        ));
    }
    let changed = RtspScope {
        peer: "127.0.0.2:554".parse().unwrap(),
        authority: scope.authority.clone(),
    };
    assert!(validate_stream_uri(STREAM, &changed).is_err());
}

fn media2_config(peer: SocketAddr) -> ClientConfig {
    ClientConfig {
        media_version: MediaVersion::Media2,
        ..config(peer)
    }
}

fn media2_soap(body: &str) -> String {
    soap(body).replace(
        "<s:Body>",
        "<s:Body xmlns:tr2=\"http://www.onvif.org/ver20/media/wsdl\">",
    )
}

fn media2_services(uri: &str) -> String {
    ok(soap(&format!(
        "<tds:GetServicesResponse><tds:Service><tds:Namespace>http://www.onvif.org/ver20/media/wsdl</tds:Namespace><tds:XAddr>{uri}</tds:XAddr><tds:Version><tt:Major>24</tt:Major><tt:Minor>6</tt:Minor></tds:Version></tds:Service></tds:GetServicesResponse>"
    )))
}

fn media2_profiles(encoder: bool) -> String {
    let configs = if encoder {
        "<tr2:Configurations><tr2:VideoEncoder token=\"hevc-encoder\"><tt:Encoding>H265</tt:Encoding><tt:Resolution><tt:Width>3840</tt:Width><tt:Height>2160</tt:Height></tt:Resolution></tr2:VideoEncoder></tr2:Configurations>"
    } else {
        ""
    };
    ok(media2_soap(&format!(
        "<tr2:GetProfilesResponse><tr2:Profiles token=\"{TOKEN}\"><tr2:Name>Private Media2 Main</tr2:Name>{configs}</tr2:Profiles></tr2:GetProfilesResponse>"
    )))
}

fn media2_stream(uri: &str) -> String {
    let uri = uri.replace('&', "&amp;");
    ok(media2_soap(&format!(
        "<tr2:GetStreamUriResponse><tr2:Uri>{uri}</tr2:Uri></tr2:GetStreamUriResponse>"
    )))
}

#[test]
fn media2_only_camera_negotiates_h265_with_scoped_digest_and_explicit_validity_basis() {
    let server = Server::start(|peer| {
        vec![
            challenge(REALM),
            media2_services(&format!("http://{peer}/onvif/media2_service")),
            challenge(REALM),
            media2_profiles(true),
            challenge(REALM),
            media2_stream(STREAM),
        ]
    });
    let cx = Context::new(server.peer);
    let result = run(&media2_config(server.peer), Some(TOKEN), &cx).unwrap();
    assert_eq!(result.exchanges, 6);
    assert_eq!(result.discovery.media_version(), MediaVersion::Media2);
    assert!(matches!(&result.discovery, MediaDiscovery::Media2(service)
        if service.version == ServiceVersion { major: 24, minor: 6 }));
    let selected = result.selection.as_ref().unwrap();
    assert_eq!(
        selected.profile.video.as_ref().unwrap().encoding,
        VideoEncoding::H265
    );
    assert_eq!(selected.stream.uri, STREAM);
    assert_eq!(selected.stream.validity, StreamValidity::Media2Indefinite);
    assert!(selected.stream.is_stable());
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 3);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    for (index, request) in requests.iter().enumerate() {
        let target = if index < 2 {
            "/onvif/device_service"
        } else {
            "/onvif/media2_service"
        };
        assert!(request.starts_with(&format!("POST {target} HTTP/1.1\r\n")));
        assert_eq!(request.contains("Authorization: Digest "), index % 2 == 1);
        if index % 2 == 1 {
            assert!(request.contains(&format!("uri=\"{target}\"")));
        }
        assert!(!request.contains("fixture-password"));
        assert!(!request.contains("GetCapabilities"));
    }
    assert!(requests[0].contains("<tds:IncludeCapability>false</tds:IncludeCapability>"));
    assert!(requests[2].contains("<tr2:Type>VideoEncoder</tr2:Type>"));
    assert!(requests[5].contains("<tr2:Protocol>RTSP</tr2:Protocol>"));
    let debug = format!("{result:?} {:?} {:?}", result.discovery, selected.stream);
    for private in [
        STREAM,
        TOKEN,
        REALM,
        "Private Media2 Main",
        "media2_service",
    ] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn media2_inventory_does_not_acquire_a_uri_and_preserves_missing_video() {
    let server = Server::start(|peer| {
        vec![
            media2_services(&format!("http://{peer}/onvif/media2_service")),
            media2_profiles(false),
        ]
    });
    let mut cfg = media2_config(server.peer);
    cfg.rtsp = None;
    let result = run(&cfg, None, &Context::new(server.peer)).unwrap();
    assert_eq!(result.exchanges, 2);
    assert_eq!(result.profiles[0].video, None);
    assert!(result.selection.is_none());
    assert!(
        server
            .requests()
            .iter()
            .all(|request| !request.contains("GetStreamUri"))
    );
}

#[test]
fn media2_missing_service_does_not_fall_back_to_media1() {
    let server = Server::start(|peer| {
        let body = soap(&format!(
            "<tds:GetServicesResponse><tds:Service><tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace><tds:XAddr>http://{peer}/onvif/media_service</tds:XAddr><tds:Version><tt:Major>2</tt:Major><tt:Minor>0</tt:Minor></tds:Version></tds:Service></tds:GetServicesResponse>"
        ));
        vec![ok(body)]
    });
    let cx = Context::new(server.peer);
    assert!(matches!(
        run(&media2_config(server.peer), Some(TOKEN), &cx),
        Err(ClientError::Unsupported)
    ));
    assert_eq!(server.requests().len(), 1);
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn media2_foreign_service_origin_and_path_fail_before_followup_or_credentials() {
    for variant in 0..5 {
        let server = Server::start(|peer| {
            let uri = match variant {
                0 => format!("http://127.0.0.2:{}/onvif/media2_service", peer.port()),
                1 => format!("http://{peer}/onvif-other/media"),
                2 => format!("http://{peer}/onvif/../admin"),
                3 => format!("https://{peer}/onvif/media2_service"),
                _ => format!("http://{peer}/onvif/%2e%2e/admin"),
            };
            vec![media2_services(&uri)]
        });
        let cx = Context::new(server.peer);
        assert!(matches!(
            run(&media2_config(server.peer), None, &cx),
            Err(ClientError::Scope)
        ));
        assert_eq!(server.requests().len(), 1);
        assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn media2_missing_video_and_wrong_profile_namespace_refuse_before_uri_request() {
    for variant in 0..3 {
        let server = Server::start(|peer| {
            vec![
                media2_services(&format!("http://{peer}/onvif/media2_service")),
                match variant {
                    0 => media2_profiles(false),
                    1 => profiles(),
                    _ => media2_profiles(true),
                },
            ]
        });
        let selected = if variant == 2 {
            "absent-profile"
        } else {
            TOKEN
        };
        let result = run(
            &media2_config(server.peer),
            Some(selected),
            &Context::new(server.peer),
        );
        assert!(matches!(
            result,
            Err(ClientError::Profile | ClientError::Wire(WireError::UnexpectedResponse))
        ));
        assert_eq!(server.requests().len(), 2);
        assert!(
            server
                .requests()
                .iter()
                .all(|request| !request.contains("GetStreamUri"))
        );
    }
}

#[test]
fn media2_returned_uri_remains_independently_pinned() {
    let server = Server::start(|peer| {
        vec![
            media2_services(&format!("http://{peer}/onvif/media2_service")),
            media2_profiles(true),
            media2_stream("rtsp://127.0.0.2:554/private-main"),
        ]
    });
    assert!(matches!(
        run(
            &media2_config(server.peer),
            Some(TOKEN),
            &Context::new(server.peer)
        ),
        Err(ClientError::Scope)
    ));
    assert_eq!(server.requests().len(), 3);
}
