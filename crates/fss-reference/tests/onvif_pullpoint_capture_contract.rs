#![forbid(unsafe_code)]
//! Real native HTTP loopback coverage for bounded ONVIF PullPoint acquisition.
//! Fixture credentials, deterministic message IDs and sink receipts are test-only.
//! Durable metadata publication is covered by onvif_metadata_custody separately.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fss_core::ContentDigest;
use fss_reference::onvif::client::{ClientError, DigestConfig, OnvifContext};
use fss_reference::onvif::http::{
    HttpAuthority, HttpDenial, HttpError, HttpExchange, HttpLimits, HttpOperation, HttpRoute,
};
use fss_reference::onvif::metadata::MetadataError;
use fss_reference::onvif::pullpoint::{
    CaptureStop, PullPointConfig, PullPointControl, PullPointError, RetainedBatch,
    RetainedProgress, SubscriptionState, capture, capture_with_control, capture_with_progress,
    route_in_service_root, unsubscribe_existing, validate_config,
};
use fss_reference::onvif::wire::{
    create_pull_point_request, get_profiles_request, parse_pull_point_subscription,
};
use fss_reference::rtsp::authentication::{
    DigestAuthorization, DigestChallenge, DigestCredentials, DigestPolicy,
};

const REALM: &str = "fixture-camera";
const SUBSCRIPTION: &str = "/onvif/subscription?Id=fixture&channel=1";

struct Server {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}
impl Server {
    fn start(replies: impl FnOnce(SocketAddr) -> Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
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
                let mut chunk = [0; 1024];
                loop {
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&chunk[..count]);
                    assert!(request.len() <= 32768);
                    if let Some(head) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..head]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if request.len() == head + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let id = message_id(&request);
                captured.lock().unwrap().push(request);
                let reply = if let Some(body) = reply.strip_prefix("SOAP:") {
                    let body = body.replace("REQUEST_ID", &id);
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    reply
                };
                // Empty replies intentionally close after accepting the complete request.
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
fn message_id(request: &str) -> String {
    let marker = ":MessageID>";
    let start = request.find(marker).expect("request has MessageID") + marker.len();
    let end = request[start..].find("</").unwrap() + start;
    request[start..end].to_owned()
}

struct Context {
    start: Instant,
    peer: SocketAddr,
    cancelled: AtomicBool,
    revoked: AtomicBool,
    auth_calls: AtomicU32,
    connects: AtomicU32,
    ids: AtomicU32,
    repeat_ids: bool,
    cancel_on_create_release: bool,
    cancel_on_subscription_release: bool,
    offset_ns: AtomicU64,
}
impl Context {
    fn new(peer: SocketAddr) -> Self {
        Self {
            start: Instant::now(),
            peer,
            cancelled: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            auth_calls: AtomicU32::new(0),
            connects: AtomicU32::new(0),
            ids: AtomicU32::new(0),
            repeat_ids: false,
            cancel_on_create_release: false,
            cancel_on_subscription_release: false,
            offset_ns: AtomicU64::new(0),
        }
    }
    fn now(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64 + 1 + self.offset_ns.load(Ordering::SeqCst)
    }
}
impl HttpAuthority for Context {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        operation: HttpOperation,
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), HttpDenial> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(HttpDenial::Cancelled);
        }
        if self.revoked.load(Ordering::SeqCst) {
            return Err(HttpDenial::Revoked);
        }
        if self.now() >= deadline_ns {
            return Err(HttpDenial::Deadline);
        }
        if route.peer() != self.peer
            || route.authority() != self.peer.to_string()
            || route.generation() != 1
            || !route.is_event_subscription()
            || !matches!(route.target(), "/onvif/events" | SUBSCRIPTION)
            || now_ns > self.now()
            || deadline_ns > 7_000_000_000
        {
            return Err(HttpDenial::Unauthorized);
        }
        if operation == HttpOperation::Connect {
            self.connects.fetch_add(1, Ordering::SeqCst);
        }
        if self.cancel_on_create_release
            && operation == HttpOperation::Release
            && route.target() == "/onvif/events"
        {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        if self.cancel_on_subscription_release
            && operation == HttpOperation::Release
            && route.target() == SUBSCRIPTION
        {
            self.cancelled.store(true, Ordering::SeqCst);
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
    fn event_request_id(&self) -> Result<[u8; 16], ClientError> {
        let n = self.ids.fetch_add(1, Ordering::SeqCst) + 1;
        Ok([if self.repeat_ids { 7 } else { n as u8 }; 16])
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

fn config(peer: SocketAddr) -> PullPointConfig {
    PullPointConfig {
        events: HttpRoute::event_service(
            peer,
            &peer.to_string(),
            "/onvif/events",
            1,
            ContentDigest::sha256(b"fixture-owner-plaintext-subscription-approval"),
        )
        .unwrap(),
        service_root: "/onvif".into(),
        auth: None,
        limits: HttpLimits::default(),
        deadline_ns: 7_000_000_000,
        max_steps: 10000,
        max_pulls: 2,
        max_renewals: 0,
        pull_timeout_seconds: 1,
        message_limit: 16,
        lifetime_seconds: 120,
    }
}
fn soap(body: &str, relates: &str) -> String {
    format!(
        "SOAP:<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" xmlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:tns1=\"http://www.onvif.org/ver10/topics\"><s:Header><a:RelatesTo>{relates}</a:RelatesTo></s:Header><s:Body>{body}</s:Body></s:Envelope>"
    )
}
fn created_uri(uri: &str, termination: &str) -> String {
    let uri = uri.replace('&', "&amp;");
    soap(
        &format!(
            "<tev:CreatePullPointSubscriptionResponse><tev:SubscriptionReference><a:Address>{uri}</a:Address><a:ReferenceParameters><v:SubscriptionId xmlns:v=\"urn:fixture\">exact-opaque</v:SubscriptionId></a:ReferenceParameters></tev:SubscriptionReference><wsnt:CurrentTime>2026-10-27T00:00:00Z</wsnt:CurrentTime><wsnt:TerminationTime>{termination}</wsnt:TerminationTime></tev:CreatePullPointSubscriptionResponse>"
        ),
        "REQUEST_ID",
    )
}
fn created(peer: SocketAddr) -> String {
    created_uri(
        &format!("http://{peer}{SUBSCRIPTION}"),
        "2026-10-27T00:02:00Z",
    )
}
fn pulled(count: usize) -> String {
    let notification = "<wsnt:NotificationMessage><wsnt:Topic Dialect=\"http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet\">tns1:RuleEngine/CellMotionDetector/Motion</wsnt:Topic><wsnt:Message><tt:Message UtcTime=\"2026-10-27T00:00:01Z\" PropertyOperation=\"Changed\"><tt:Data><tt:SimpleItem Name=\"IsMotion\" Value=\"false\"/></tt:Data></tt:Message></wsnt:Message></wsnt:NotificationMessage>";
    soap(
        &format!(
            "<tev:PullMessagesResponse><tev:CurrentTime>2026-10-27T00:00:01Z</tev:CurrentTime><tev:TerminationTime>2026-10-27T00:02:00Z</tev:TerminationTime>{}</tev:PullMessagesResponse>",
            notification.repeat(count)
        ),
        "REQUEST_ID",
    )
}
fn unsubscribed() -> String {
    soap("<wsnt:UnsubscribeResponse/>", "REQUEST_ID")
}
fn challenge(realm: &str) -> String {
    format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{realm}\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
    )
}
fn receipt(source: &[u8]) -> RetainedBatch {
    RetainedBatch {
        identity: ContentDigest::sha256(source),
        root: ContentDigest::sha256(&[source, b"fixture-root"].concat()),
    }
}

#[test]
fn real_http_retains_duplicates_and_empty_batches_before_confirmed_cleanup() {
    let server = Server::start(|peer| vec![created(peer), pulled(2), pulled(0), unsubscribed()]);
    let cx = Context::new(server.peer);
    let mut sources = Vec::new();
    let report = capture(&config(server.peer), &cx, |batch| {
        assert_eq!(batch.route.target(), SUBSCRIPTION);
        assert_eq!(batch.pull_index as usize, sources.len());
        assert!(batch.started_ns <= batch.completed_ns);
        assert!(batch.subscription_started_ns <= batch.subscription_completed_ns);
        assert!(!batch.authenticated);
        assert_ne!(batch.message_id, batch.subscription_message_id);
        assert!(
            std::str::from_utf8(batch.subscription_response)
                .unwrap()
                .contains("exact-opaque")
        );
        sources.push(batch.source.to_vec());
        Ok(receipt(batch.source))
    })
    .unwrap();
    assert_eq!(report.pulls, 2);
    assert_eq!(report.notifications, 2);
    assert_eq!(report.retained.len(), 2);
    assert_eq!(report.exchanges, 4);
    assert_eq!(report.stop, CaptureStop::PullLimit);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    assert!(report.cleanup_error.is_none());
    assert!(report.subscription_response().is_some());
    let requests = server.requests();
    let ids: std::collections::BTreeSet<_> =
        requests.iter().map(|request| message_id(request)).collect();
    assert_eq!(ids.len(), 4);
    for request in &requests[1..] {
        assert!(request.starts_with(&format!("POST {SUBSCRIPTION} HTTP/1.1")));
        assert!(request.contains("exact-opaque"));
        assert!(request.contains("IsReferenceParameter"));
    }
    let debug = format!("{report:?}");
    for private in ["exact-opaque", "SubscriptionId", SUBSCRIPTION, "IsMotion"] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn digest_retries_reuse_logical_message_ids_and_sign_exact_query_targets() {
    let server = Server::start(|peer| {
        vec![
            challenge(REALM),
            created(peer),
            challenge(REALM),
            pulled(1),
            challenge(REALM),
            unsubscribed(),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_pulls = 1;
    cfg.auth = Some(DigestConfig {
        expected_realm: REALM.into(),
        policy: DigestPolicy::default(),
    });
    let report = capture(&cfg, &cx, |batch| {
        assert!(batch.authenticated);
        Ok(receipt(batch.source))
    })
    .unwrap();
    assert_eq!(report.exchanges, 6);
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 3);
    let requests = server.requests();
    for pair in requests.chunks_exact(2) {
        assert_eq!(message_id(&pair[0]), message_id(&pair[1]));
        assert!(!pair[0].contains("Authorization: Digest "));
        assert!(pair[1].contains("Authorization: Digest "));
        assert!(!pair[1].contains("fixture-password"));
    }
    assert!(requests[3].contains(&format!("uri=\"{SUBSCRIPTION}\"")));
    assert_ne!(message_id(&requests[0]), message_id(&requests[2]));
    assert_ne!(message_id(&requests[2]), message_id(&requests[4]));
}

#[test]
fn failed_second_sink_preserves_first_receipt_and_still_unsubscribes() {
    let server = Server::start(|peer| vec![created(peer), pulled(1), pulled(0), unsubscribed()]);
    let mut calls = 0;
    let failure = capture(&config(server.peer), &Context::new(server.peer), |batch| {
        calls += 1;
        if calls == 2 {
            Err(MetadataError::Custody)
        } else {
            Ok(receipt(batch.source))
        }
    })
    .unwrap_err();
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.pulls, 1);
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(failure.code(), "ERR-ONVIF-METADATA-CUSTODY-001");
    assert_eq!(server.requests().len(), 4);
}

#[test]
fn cancellation_after_sink_never_erases_durable_receipt_or_grants_cleanup() {
    let server = Server::start(|peer| vec![created(peer), pulled(1)]);
    let cx = Context::new(server.peer);
    let failure = capture(&config(server.peer), &cx, |batch| {
        cx.cancelled.store(true, Ordering::SeqCst);
        Ok(receipt(batch.source))
    })
    .unwrap_err();
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert_eq!(
        failure.report.cleanup_error,
        Some("ERR-ONVIF-CANCELLED-001")
    );
    assert_eq!(server.requests().len(), 2);
    assert!(failure.report.subscription_response().is_some());
}

#[test]
fn revoked_owner_cannot_send_another_poll_or_cleanup() {
    let server = Server::start(|peer| vec![created(peer), pulled(1)]);
    let cx = Context::new(server.peer);
    let failure = capture(&config(server.peer), &cx, |batch| {
        cx.revoked.store(true, Ordering::SeqCst);
        Ok(receipt(batch.source))
    })
    .unwrap_err();
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert_eq!(
        failure.report.cleanup_error,
        Some("ERR-ONVIF-AUTHORITY-001")
    );
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn unconfirmed_cleanup_preserves_source_and_explicit_active_state() {
    let server = Server::start(|peer| {
        vec![
            created(peer),
            pulled(0),
            soap("<wsnt:WrongResponse/>", "REQUEST_ID"),
        ]
    });
    let mut cfg = config(server.peer);
    cfg.max_pulls = 1;
    let failure = capture(&cfg, &Context::new(server.peer), |batch| {
        Ok(receipt(batch.source))
    })
    .unwrap_err();
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert!(failure.report.cleanup_error.is_some());
    assert!(failure.report.subscription_response().is_some());
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn ambiguous_create_is_not_retried_and_has_no_invented_endpoint() {
    let server = Server::start(|_| vec![String::new()]);
    let failure = capture(&config(server.peer), &Context::new(server.peer), |_| {
        panic!("no source")
    })
    .unwrap_err();
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Indeterminate
    );
    assert!(failure.report.retained.is_empty());
    assert!(failure.report.subscription_response().is_none());
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn too_short_reported_lease_is_cleaned_without_polling() {
    let server = Server::start(|peer| {
        vec![
            created_uri(
                &format!("http://{peer}{SUBSCRIPTION}"),
                "2026-10-27T00:00:02Z",
            ),
            unsubscribed(),
        ]
    });
    let failure = capture(&config(server.peer), &Context::new(server.peer), |_| {
        panic!("no source")
    })
    .unwrap_err();
    assert!(matches!(failure.error, PullPointError::Lease));
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(server.requests().len(), 2);
    assert!(!server.requests()[1].contains("PullMessages"));
}

#[test]
fn response_cannot_exceed_requested_message_limit() {
    let server = Server::start(|peer| vec![created(peer), pulled(2), unsubscribed()]);
    let mut cfg = config(server.peer);
    cfg.message_limit = 1;
    let failure = capture(&cfg, &Context::new(server.peer), |_| {
        panic!("unaccepted source")
    })
    .unwrap_err();
    assert!(matches!(failure.error, PullPointError::MessageLimit));
    assert!(failure.report.retained.is_empty());
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
}

#[test]
fn response_correlation_mismatch_is_refused_before_retention() {
    let server = Server::start(|peer| {
        vec![
            created(peer),
            pulled(1).replace("REQUEST_ID", "urn:wrong:request"),
            unsubscribed(),
        ]
    });
    let failure = capture(&config(server.peer), &Context::new(server.peer), |_| {
        panic!("mismatched source")
    })
    .unwrap_err();
    assert!(failure.report.retained.is_empty());
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn reused_owner_entropy_is_refused_before_a_second_operation() {
    let server = Server::start(|peer| vec![created(peer)]);
    let mut cx = Context::new(server.peer);
    cx.repeat_ids = true;
    let failure = capture(&config(server.peer), &cx, |_| panic!("no source")).unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-ENTROPY-001");
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert_eq!(failure.report.cleanup_error, Some("ERR-ONVIF-ENTROPY-001"));
    assert!(failure.report.subscription_response().is_some());
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn clock_budget_stops_polling_early_and_preserves_cleanup_reservation() {
    let server = Server::start(|peer| vec![created(peer), pulled(0), unsubscribed()]);
    let cx = Context::new(server.peer);
    let report = capture(&config(server.peer), &cx, |batch| {
        cx.offset_ns.store(4_100_000_000, Ordering::SeqCst);
        Ok(receipt(batch.source))
    })
    .unwrap();
    assert_eq!(report.pulls, 1);
    assert_eq!(report.stop, CaptureStop::DeadlineReserve);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn malicious_epr_never_expands_origin_or_service_subtree() {
    for suffix in [
        "/outside/sub",
        "/onvif-other/sub",
        "/onvif/../admin",
        "/onvif/sub?x=%2e",
        "/onvif/sub#fragment",
    ] {
        let server = Server::start(|peer| {
            vec![created_uri(
                &format!("http://{peer}{suffix}"),
                "2026-10-27T00:02:00Z",
            )]
        });
        let failure = capture(&config(server.peer), &Context::new(server.peer), |_| {
            panic!("no source")
        })
        .unwrap_err();
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Indeterminate
        );
        assert_eq!(server.requests().len(), 1);
        assert!(failure.report.subscription_response().is_some());
    }
    let server = Server::start(|_| {
        vec![created_uri(
            "http://127.0.0.1:1/onvif/sub",
            "2026-10-27T00:02:00Z",
        )]
    });
    let failure = capture(&config(server.peer), &Context::new(server.peer), |_| {
        panic!("no source")
    })
    .unwrap_err();
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Indeterminate
    );
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn typed_routes_do_not_upgrade_read_only_media_or_snapshot_authority() {
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let cfg = config(peer);
    let read_only = HttpRoute::new(
        peer,
        &peer.to_string(),
        "/onvif/events",
        1,
        cfg.events.plaintext_approval(),
    )
    .unwrap();
    let cx = Context::new(peer);
    let request = create_pull_point_request("http://127.0.0.1:9/onvif/events", 120)
        .unwrap()
        .with_message_id("urn:fixture:create")
        .unwrap();
    assert!(matches!(
        HttpExchange::connect(read_only.clone(), &request, None, cfg.limits, 1, 100, &cx),
        Err(HttpError::Configuration)
    ));
    assert!(matches!(
        HttpExchange::connect(
            cfg.events.clone(),
            &get_profiles_request(),
            None,
            cfg.limits,
            1,
            100,
            &cx
        ),
        Err(HttpError::Configuration)
    ));
    assert!(cfg.events.snapshot("http://127.0.0.1:9/image.jpg").is_err());
    assert!(
        read_only
            .event_subscription("http://127.0.0.1:9/onvif/sub?Id=1", "/onvif")
            .is_err()
    );
    assert!(!route_in_service_root(&cfg.events, ""));
    assert!(!route_in_service_root(&cfg.events, "/onvif/.."));
    assert!(route_in_service_root(&cfg.events, "/onvif"));
    assert_ne!(cfg.events.digest(), read_only.digest());
    let without_id = create_pull_point_request("http://127.0.0.1:9/onvif/events", 120).unwrap();
    assert!(matches!(
        HttpExchange::connect(cfg.events, &without_id, None, cfg.limits, 1, 100, &cx),
        Err(HttpError::Configuration)
    ));
}

#[test]
fn configuration_refuses_before_network_or_source_custody() {
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mut cfg = config(peer);
    for bad in [0, 65] {
        cfg.max_pulls = bad;
        assert!(validate_config(&cfg).is_err());
        let failure = capture(&cfg, &Context::new(peer), |_| panic!("no source")).unwrap_err();
        assert_eq!(failure.report.exchanges, 0);
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::NotCreated
        );
    }
    cfg.max_pulls = 1;
    cfg.limits.body_bytes = 262145;
    assert!(validate_config(&cfg).is_err());
    cfg.limits.body_bytes = 262144;
    cfg.max_steps = 1024;
    assert!(validate_config(&cfg).is_err());
    cfg.max_steps = 10000;
    cfg.max_renewals = 5;
    assert!(validate_config(&cfg).is_err());
    cfg.max_renewals = 1;
    assert!(matches!(
        capture(&cfg, &Context::new(peer), |_| panic!("no source"))
            .unwrap_err()
            .error,
        PullPointError::Configuration
    ));
}

#[test]
fn complete_create_source_survives_immediate_post_release_cancellation() {
    let server = Server::start(|peer| vec![created(peer)]);
    let mut cx = Context::new(server.peer);
    cx.cancel_on_create_release = true;
    let failure = capture(&config(server.peer), &cx, |_| panic!("no source")).unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-CANCELLED-001");
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Indeterminate
    );
    assert!(failure.report.retained.is_empty());
    assert!(failure.report.subscription_response().is_some());
    assert!(failure.report.subscription_message_id().is_some());
    assert!(failure.report.subscription_started_ns().is_some());
    assert!(failure.report.subscription_completed_ns().is_some());
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn durable_control_callbacks_precede_create_dispatch_and_first_poll() {
    let server = Server::start(|peer| vec![created(peer), pulled(0), unsubscribed()]);
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_pulls = 1;
    let intent_receipt = receipt(b"fixture:create-intent");
    let stage = AtomicU32::new(0);
    let report = capture_with_control(
        &cfg,
        &cx,
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent {
                events,
                service_root,
                message_id,
                started_ns,
                lifetime_seconds,
            } => {
                assert_eq!(stage.load(Ordering::SeqCst), 0);
                assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
                assert!(server.requests().is_empty());
                assert_eq!(events, &cfg.events);
                assert_eq!(service_root, cfg.service_root);
                assert!(message_id.starts_with("urn:fss:onvif:"));
                assert!(started_ns > 0);
                assert_eq!(lifetime_seconds, cfg.lifetime_seconds);
                stage.store(1, Ordering::SeqCst);
                Ok(intent_receipt)
            }
            PullPointControl::CreateOutcome {
                source,
                message_id: observed_id,
                started_ns,
                completed_ns,
                authenticated,
                http_status,
                soap_content_type,
            } => {
                assert_eq!(stage.load(Ordering::SeqCst), 1);
                let requests = server.requests();
                assert_eq!(requests.len(), 1);
                assert_eq!(observed_id, message_id(&requests[0]));
                assert!(completed_ns.is_some_and(|end| started_ns <= end));
                assert!(!authenticated);
                assert_eq!(http_status, 200);
                assert!(soap_content_type);
                stage.store(2, Ordering::SeqCst);
                Ok(receipt(source))
            }
            PullPointControl::Created {
                source,
                message_id: created_id,
                started_ns,
                completed_ns,
                authenticated,
            } => {
                assert_eq!(stage.load(Ordering::SeqCst), 2);
                let requests = server.requests();
                assert_eq!(requests.len(), 1);
                assert_eq!(created_id, message_id(&requests[0]));
                assert!(started_ns <= completed_ns);
                assert!(!authenticated);
                assert!(
                    std::str::from_utf8(source)
                        .unwrap()
                        .contains("exact-opaque")
                );
                stage.store(3, Ordering::SeqCst);
                Ok(receipt(source))
            }
            PullPointControl::Unsubscribed { source, route, .. } => {
                assert_eq!(stage.load(Ordering::SeqCst), 5);
                assert_eq!(route.target(), SUBSCRIPTION);
                stage.store(6, Ordering::SeqCst);
                Ok(receipt(source))
            }
            PullPointControl::UnsubscribeIntent {
                message_id, route, ..
            } => {
                assert_eq!(stage.load(Ordering::SeqCst), 3);
                assert_eq!(server.requests().len(), 2);
                assert_eq!(route.target(), SUBSCRIPTION);
                stage.store(4, Ordering::SeqCst);
                Ok(receipt(message_id.as_bytes()))
            }
            PullPointControl::UnsubscribeOutcome { source, .. } => {
                assert_eq!(stage.load(Ordering::SeqCst), 4);
                assert_eq!(server.requests().len(), 3);
                stage.store(5, Ordering::SeqCst);
                Ok(receipt(source))
            }
        },
        |batch| {
            assert_eq!(stage.load(Ordering::SeqCst), 3);
            assert_eq!(server.requests().len(), 2);
            Ok(receipt(batch.source))
        },
    )
    .unwrap();
    assert_eq!(stage.load(Ordering::SeqCst), 6);
    assert!(report.create_outcome.is_some());
    assert!(report.unsubscribe_intent.is_some());
    assert!(report.unsubscribe_outcome.is_some());
    assert!(report.unsubscribe_receipt.is_some());
    assert_eq!(report.create_intent, Some(intent_receipt));
    assert_eq!(
        report.created_subscription,
        Some(receipt(report.subscription_response().unwrap()))
    );
    assert_eq!(report.retained.len(), 1);
    assert_eq!(report.pulls, 1);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn failed_create_intent_custody_refuses_before_any_connection_or_dispatch() {
    let server = Server::start(|_| vec![String::new()]);
    let cx = Context::new(server.peer);
    let failure = capture_with_control(
        &config(server.peer),
        &cx,
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Err(MetadataError::Custody),
            PullPointControl::CreateOutcome { .. }
            | PullPointControl::Created { .. }
            | PullPointControl::Unsubscribed { .. }
            | PullPointControl::UnsubscribeIntent { .. }
            | PullPointControl::UnsubscribeOutcome { .. } => {
                panic!("Create was never admitted")
            }
        },
        |_| panic!("no poll was admitted"),
    )
    .unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-METADATA-CUSTODY-001");
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::NotCreated
    );
    assert!(failure.report.create_intent.is_none());
    assert!(failure.report.created_subscription.is_none());
    assert!(failure.report.subscription_response().is_none());
    assert!(failure.report.retained.is_empty());
    assert_eq!(failure.report.exchanges, 0);
    assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
    assert!(server.requests().is_empty());
}

#[test]
fn rejected_complete_create_replies_reach_custody_without_followup_dispatch() {
    for case in [
        "malformed-soap",
        "http-refusal",
        "non-soap",
        "wrong-correlation",
        "missing-correlation",
        "foreign-authority",
        "outside-service-root",
        "authentication-required",
    ] {
        let server = Server::start(|peer| {
            let response = match case {
                "malformed-soap" => "SOAP:<private-incomplete-source".to_owned(),
                "http-refusal" => {
                    let body = "private-refused-create";
                    format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                }
                "non-soap" => {
                    let body = "private-non-soap-create";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                }
                "wrong-correlation" => created(peer).replace("REQUEST_ID", "urn:foreign:create"),
                "missing-correlation" => {
                    created(peer).replace("<a:RelatesTo>REQUEST_ID</a:RelatesTo>", "")
                }
                "foreign-authority" => created_uri(
                    "http://127.0.0.2/onvif/subscription?private=unapproved",
                    "2026-10-27T00:02:00Z",
                ),
                "outside-service-root" => created_uri(
                    &format!("http://{peer}/outside/subscription?private=unapproved"),
                    "2026-10-27T00:02:00Z",
                ),
                "authentication-required" => challenge(REALM),
                _ => unreachable!(),
            };
            vec![response]
        });
        let cx = Context::new(server.peer);
        let mut observed = None;
        let failure = capture_with_control(
            &config(server.peer),
            &cx,
            |event| match event {
                PullPointControl::CreateIntent { .. } => Ok(receipt(b"intent")),
                PullPointControl::CreateOutcome {
                    source,
                    message_id: actual_id,
                    started_ns,
                    completed_ns,
                    authenticated,
                    http_status,
                    soap_content_type,
                } => {
                    assert!(observed.is_none(), "one raw outcome for {case}");
                    assert_eq!(server.requests().len(), 1);
                    assert_eq!(actual_id, message_id(&server.requests()[0]));
                    assert!(completed_ns.is_some_and(|end| end >= started_ns));
                    assert!(!authenticated);
                    assert_eq!(
                        http_status,
                        match case {
                            "http-refusal" => 403,
                            "authentication-required" => 401,
                            _ => 200,
                        }
                    );
                    assert_eq!(
                        soap_content_type,
                        !matches!(
                            case,
                            "http-refusal" | "non-soap" | "authentication-required"
                        )
                    );
                    let retained = receipt(source);
                    observed = Some(retained);
                    Ok(retained)
                }
                _ => panic!("rejected {case} cannot admit a successful marker or cleanup"),
            },
            |_| panic!("rejected {case} cannot admit a poll"),
        )
        .unwrap_err();
        assert!(observed.is_some(), "complete {case} must reach custody");
        assert_eq!(failure.report.create_outcome, observed);
        assert_eq!(
            observed,
            Some(receipt(failure.report.subscription_response().unwrap()))
        );
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Indeterminate
        );
        assert!(failure.report.created_subscription.is_none());
        assert!(failure.report.unsubscribe_intent.is_none());
        assert!(failure.report.cleanup_error.is_none());
        assert_eq!(failure.report.pulls, 0);
        assert_eq!(failure.report.exchanges, 1);
        assert_eq!(server.requests().len(), 1);
        assert_eq!(cx.connects.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn create_outcome_custody_refusal_preserves_ambiguity_without_poll_or_cleanup() {
    for after_commit in [false, true] {
        let server = Server::start(|peer| vec![created(peer)]);
        let failure = capture_with_progress(
            &config(server.peer),
            &Context::new(server.peer),
            |event| match event {
                PullPointControl::CreateIntent { .. } => Ok(receipt(b"intent").into()),
                PullPointControl::CreateOutcome { source, .. } if after_commit => {
                    Ok(RetainedProgress {
                        receipt: receipt(source),
                        stop: Some(PullPointError::Client(ClientError::Budget)),
                    })
                }
                PullPointControl::CreateOutcome { .. } => Err(MetadataError::Custody),
                _ => panic!("no successful marker or cleanup after raw custody refusal"),
            },
            |_| panic!("no polling after raw custody refusal"),
        )
        .unwrap_err();
        assert!(failure.report.create_intent.is_some());
        assert_eq!(failure.report.create_outcome.is_some(), after_commit);
        assert!(failure.report.subscription_response().is_some());
        assert!(failure.report.created_subscription.is_none());
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Indeterminate
        );
        assert!(failure.report.unsubscribe_intent.is_none());
        assert_eq!(failure.report.exchanges, 1);
        assert_eq!(server.requests().len(), 1);
        if after_commit {
            assert!(matches!(
                failure.error,
                PullPointError::Client(ClientError::Budget)
            ));
        } else {
            assert!(matches!(
                failure.error,
                PullPointError::Retention(MetadataError::Custody)
            ));
        }
    }
}

#[test]
fn complete_create_outcome_precedes_post_transport_or_post_custody_cancellation() {
    for on_transport_release in [false, true] {
        let server = Server::start(|peer| vec![created(peer)]);
        let mut cx = Context::new(server.peer);
        cx.cancel_on_create_release = on_transport_release;
        let failure = capture_with_control(
            &config(server.peer),
            &cx,
            |event| match event {
                PullPointControl::CreateIntent { .. } => Ok(receipt(b"intent")),
                PullPointControl::CreateOutcome {
                    source,
                    completed_ns,
                    ..
                } => {
                    assert!(completed_ns.is_some());
                    assert_eq!(cx.cancelled.load(Ordering::SeqCst), on_transport_release);
                    cx.cancelled.store(true, Ordering::SeqCst);
                    Ok(receipt(source))
                }
                _ => panic!("cancellation cannot authorize success-marker continuation or cleanup"),
            },
            |_| panic!("cancelled owner cannot poll"),
        )
        .unwrap_err();
        assert_eq!(failure.code(), "ERR-ONVIF-CANCELLED-001");
        assert!(failure.report.create_outcome.is_some());
        assert!(failure.report.subscription_completed_ns().is_some());
        assert!(failure.report.created_subscription.is_none());
        assert!(failure.report.unsubscribe_intent.is_none());
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Indeterminate
        );
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn refused_create_authentication_retains_final_response_without_automatic_retry() {
    for wrong_realm in [false, true] {
        let server = Server::start(|_| {
            if wrong_realm {
                vec![challenge("foreign-camera")]
            } else {
                vec![challenge(REALM), challenge(REALM)]
            }
        });
        let mut cfg = config(server.peer);
        cfg.auth = Some(DigestConfig {
            expected_realm: REALM.to_owned(),
            policy: DigestPolicy::default(),
        });
        let cx = Context::new(server.peer);
        let failure = capture_with_control(
            &cfg,
            &cx,
            |event| match event {
                PullPointControl::CreateIntent { .. } => Ok(receipt(b"intent")),
                PullPointControl::CreateOutcome {
                    source,
                    authenticated,
                    http_status,
                    ..
                } => {
                    assert!(source.is_empty());
                    assert_eq!(http_status, 401);
                    assert_eq!(authenticated, !wrong_realm);
                    Ok(receipt(source))
                }
                _ => panic!("refused authentication cannot admit followup control"),
            },
            |_| panic!("refused authentication cannot poll"),
        )
        .unwrap_err();
        assert!(failure.report.create_outcome.is_some());
        assert!(failure.report.created_subscription.is_none());
        let requests = server.requests();
        assert_eq!(requests.len(), if wrong_realm { 1 } else { 2 });
        assert_eq!(
            cx.auth_calls.load(Ordering::SeqCst),
            u32::from(!wrong_realm)
        );
        if !wrong_realm {
            assert_eq!(message_id(&requests[0]), message_id(&requests[1]));
            assert!(requests[1].contains("Authorization: Digest"));
        }
    }
}

#[test]
fn failed_created_custody_prevents_poll_but_preserves_intent_and_attempts_cleanup() {
    let server = Server::start(|peer| vec![created(peer), unsubscribed()]);
    let cx = Context::new(server.peer);
    let intent_receipt = receipt(b"fixture:create-intent");
    let failure = capture_with_control(
        &config(server.peer),
        &cx,
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Ok(intent_receipt),
            PullPointControl::Created { .. } => Err(MetadataError::Custody),
            PullPointControl::UnsubscribeIntent { message_id, .. } => {
                Ok(receipt(message_id.as_bytes()))
            }
            PullPointControl::CreateOutcome { source, .. }
            | PullPointControl::Unsubscribed { source, .. }
            | PullPointControl::UnsubscribeOutcome { source, .. } => Ok(receipt(source)),
        },
        |_| panic!("Create custody must precede the first poll"),
    )
    .unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-METADATA-CUSTODY-001");
    assert_eq!(failure.report.create_intent, Some(intent_receipt));
    assert!(failure.report.created_subscription.is_none());
    assert!(failure.report.subscription_response().is_some());
    assert!(failure.report.retained.is_empty());
    assert_eq!(failure.report.pulls, 0);
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert!(failure.report.cleanup_error.is_none());
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("Unsubscribe"));
    assert!(!requests[1].contains("PullMessages"));
}

#[test]
fn zero_poll_lease_failure_retains_both_control_receipts_for_cold_recovery() {
    let server = Server::start(|peer| {
        vec![
            created_uri(
                &format!("http://{peer}{SUBSCRIPTION}"),
                "2026-10-27T00:00:02Z",
            ),
            unsubscribed(),
        ]
    });
    let intent_receipt = receipt(b"fixture:create-intent");
    let failure = capture_with_control(
        &config(server.peer),
        &Context::new(server.peer),
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Ok(intent_receipt),
            PullPointControl::UnsubscribeIntent { message_id, .. } => {
                Ok(receipt(message_id.as_bytes()))
            }
            PullPointControl::CreateOutcome { source, .. }
            | PullPointControl::Created { source, .. }
            | PullPointControl::UnsubscribeOutcome { source, .. }
            | PullPointControl::Unsubscribed { source, .. } => Ok(receipt(source)),
        },
        |_| panic!("the short lease cannot admit a poll"),
    )
    .unwrap_err();
    assert!(matches!(failure.error, PullPointError::Lease));
    assert_eq!(failure.report.create_intent, Some(intent_receipt));
    assert_eq!(
        failure.report.created_subscription,
        Some(receipt(failure.report.subscription_response().unwrap()))
    );
    assert!(failure.report.retained.is_empty());
    assert_eq!(failure.report.pulls, 0);
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn cancellation_after_control_receipt_preserves_every_acknowledged_handle() {
    for after_created in [false, true] {
        let server = Server::start(|peer| {
            if after_created {
                vec![created(peer)]
            } else {
                vec![]
            }
        });
        let cx = Context::new(server.peer);
        let intent_receipt = receipt(b"fixture:create-intent");
        let failure = capture_with_control(
            &config(server.peer),
            &cx,
            |event| match event {
                PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                    panic!("renewal disabled in this fixture")
                }
                PullPointControl::CreateIntent { .. } => {
                    if !after_created {
                        cx.cancelled.store(true, Ordering::SeqCst);
                    }
                    Ok(intent_receipt)
                }
                PullPointControl::Created { source, .. } => {
                    assert!(after_created);
                    cx.cancelled.store(true, Ordering::SeqCst);
                    Ok(receipt(source))
                }
                PullPointControl::CreateOutcome { source, .. } => Ok(receipt(source)),
                PullPointControl::Unsubscribed { .. }
                | PullPointControl::UnsubscribeIntent { .. }
                | PullPointControl::UnsubscribeOutcome { .. } => {
                    panic!("cancelled owner cannot clean up")
                }
            },
            |_| panic!("cancelled owner cannot admit a poll"),
        )
        .unwrap_err();
        assert_eq!(failure.code(), "ERR-ONVIF-CANCELLED-001");
        assert_eq!(failure.report.create_intent, Some(intent_receipt));
        assert!(failure.report.retained.is_empty());
        assert_eq!(failure.report.pulls, 0);
        if after_created {
            assert_eq!(
                failure.report.created_subscription,
                Some(receipt(failure.report.subscription_response().unwrap()))
            );
            assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
            assert_eq!(
                failure.report.cleanup_error,
                Some("ERR-ONVIF-CANCELLED-001")
            );
            assert_eq!(server.requests().len(), 1);
        } else {
            assert!(failure.report.created_subscription.is_none());
            assert!(failure.report.subscription_response().is_none());
            assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
            assert!(server.requests().is_empty());
        }
    }
}

fn acknowledged_control(event: PullPointControl<'_>) -> Result<RetainedProgress, MetadataError> {
    Ok(match event {
        PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
            panic!("renewal disabled in this fixture")
        }
        PullPointControl::CreateIntent { .. } => receipt(b"fixture:create-intent").into(),
        PullPointControl::UnsubscribeIntent { message_id, .. } => {
            receipt(message_id.as_bytes()).into()
        }
        PullPointControl::CreateOutcome { source, .. }
        | PullPointControl::Created { source, .. }
        | PullPointControl::UnsubscribeOutcome { source, .. }
        | PullPointControl::Unsubscribed { source, .. } => receipt(source).into(),
    })
}

fn renewable_created(peer: SocketAddr) -> String {
    created_uri(
        &format!("http://{peer}{SUBSCRIPTION}"),
        "2026-10-27T00:00:04Z",
    )
}
fn renewed(seconds: u32) -> String {
    soap(
        &format!(
            "<wsnt:RenewResponse><wsnt:CurrentTime>2026-10-27T00:00:00Z</wsnt:CurrentTime><wsnt:TerminationTime>2026-10-27T00:00:{seconds:02}Z</wsnt:TerminationTime></wsnt:RenewResponse>"
        ),
        "REQUEST_ID",
    )
}
fn renewable_control(event: PullPointControl<'_>) -> Result<RetainedProgress, MetadataError> {
    Ok(match event {
        PullPointControl::CreateIntent { message_id, .. }
        | PullPointControl::UnsubscribeIntent { message_id, .. }
        | PullPointControl::RenewIntent { message_id, .. } => receipt(message_id.as_bytes()).into(),
        PullPointControl::CreateOutcome { source, .. }
        | PullPointControl::Created { source, .. }
        | PullPointControl::UnsubscribeOutcome { source, .. }
        | PullPointControl::Renewed { source, .. }
        | PullPointControl::Unsubscribed { source, .. } => receipt(source).into(),
    })
}

#[test]
fn bounded_renewal_retains_intent_before_dispatch_and_preserves_original_batch_create() {
    let server = Server::start(|peer| {
        vec![
            renewable_created(peer),
            pulled(1),
            renewed(30),
            pulled(0),
            unsubscribed(),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_renewals = 1;
    let create_digest = std::cell::Cell::new(None);
    let report = capture_with_progress(
        &cfg,
        &cx,
        |event| {
            match &event {
                PullPointControl::Created { source, .. } => {
                    create_digest.set(Some(ContentDigest::sha256(source)))
                }
                PullPointControl::RenewIntent {
                    route,
                    renewal_index,
                    lifetime_seconds,
                    ..
                } => {
                    assert_eq!(
                        server.requests().len(),
                        2,
                        "intent must precede the Renew socket"
                    );
                    assert_eq!(*renewal_index, 0);
                    assert_eq!(*lifetime_seconds, cfg.lifetime_seconds);
                    assert_eq!(route.target(), SUBSCRIPTION);
                }
                PullPointControl::Renewed {
                    completed_ns,
                    http_status,
                    soap_content_type,
                    ..
                } => {
                    assert_eq!(
                        server.requests().len(),
                        3,
                        "response custody must precede the next poll"
                    );
                    assert!(completed_ns.is_some());
                    assert_eq!(*http_status, 200);
                    assert!(*soap_content_type);
                }
                _ => {}
            }
            renewable_control(event)
        },
        |batch| {
            assert_eq!(
                Some(ContentDigest::sha256(batch.subscription_response)),
                create_digest.get()
            );
            if batch.pull_index == 0 {
                cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
            }
            Ok(receipt(batch.source).into())
        },
    )
    .unwrap();
    assert_eq!(report.renewals, 1);
    assert_eq!(report.renewal_intents.len(), 1);
    assert_eq!(report.renewal_outcomes.len(), 1);
    assert_eq!(report.pulls, 2);
    assert_eq!(report.exchanges, 5);
    assert_eq!(report.stop, CaptureStop::PullLimit);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[2].contains("<wsnt:Renew>"));
    assert!(requests[2].contains("exact-opaque"));
    assert!(requests[2].contains("PT120S"));
    let ids: std::collections::BTreeSet<_> =
        requests.iter().map(|request| message_id(request)).collect();
    assert_eq!(
        ids.len(),
        5,
        "every logical operation needs a fresh identity"
    );
}

#[test]
fn renewal_count_ceiling_stops_before_another_attempt_and_preserves_cleanup_reserve() {
    let server = Server::start(|peer| {
        vec![
            renewable_created(peer),
            pulled(0),
            renewed(4),
            pulled(0),
            unsubscribed(),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_pulls = 3;
    cfg.max_renewals = 1;
    let report = capture_with_progress(&cfg, &cx, renewable_control, |batch| {
        cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
        Ok(receipt(batch.source).into())
    })
    .unwrap();
    assert_eq!(report.renewals, 1);
    assert_eq!(report.pulls, 2);
    assert_eq!(report.stop, CaptureStop::LeaseReserve);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    assert_eq!(server.requests().len(), 5);
}

#[test]
fn renewed_remote_lease_never_extends_the_original_whole_session_deadline() {
    let server = Server::start(|peer| {
        vec![
            renewable_created(peer),
            pulled(0),
            renewed(30),
            pulled(0),
            unsubscribed(),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_pulls = 3;
    cfg.max_renewals = 4;
    let report = capture_with_progress(&cfg, &cx, renewable_control, |batch| {
        cx.offset_ns.fetch_add(
            if batch.pull_index == 0 {
                600_000_000
            } else {
                5_000_000_000
            },
            Ordering::SeqCst,
        );
        Ok(receipt(batch.source).into())
    })
    .unwrap();
    assert_eq!(report.renewals, 1);
    assert_eq!(report.pulls, 2);
    assert_eq!(report.stop, CaptureStop::DeadlineReserve);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    assert_eq!(server.requests().len(), 5);
}

#[test]
fn rejected_renewal_bodies_are_retained_before_failure_and_never_admit_another_poll() {
    let malformed = soap(
        "<wsnt:RenewResponse><private>secret-malformed-reply</private></wsnt:RenewResponse>",
        "REQUEST_ID",
    );
    let mismatch = renewed(30).replace("REQUEST_ID", "urn:wrong:renewal");
    let unsupported = "HTTP/1.1 503 Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 17\r\nConnection: close\r\n\r\nprivate-http-body".to_owned();
    for reply in [malformed, mismatch, unsupported, challenge(REALM)] {
        let server =
            Server::start(|peer| vec![renewable_created(peer), pulled(0), reply, unsubscribed()]);
        let cx = Context::new(server.peer);
        let mut cfg = config(server.peer);
        cfg.max_renewals = 1;
        let observed = std::cell::Cell::new(false);
        let failure = capture_with_progress(
            &cfg,
            &cx,
            |event| {
                if let PullPointControl::Renewed { .. } = &event {
                    observed.set(true);
                }
                renewable_control(event)
            },
            |batch| {
                assert_eq!(
                    batch.pull_index, 0,
                    "rejected Renew cannot permit another poll"
                );
                cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
                Ok(receipt(batch.source).into())
            },
        )
        .unwrap_err();
        assert!(
            observed.get(),
            "a complete rejected HTTP body remains observable"
        );
        assert_eq!(failure.report.renewals, 0);
        assert_eq!(failure.report.renewal_intents.len(), 1);
        assert_eq!(failure.report.renewal_outcomes.len(), 1);
        assert_eq!(failure.report.retained.len(), 1);
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Unsubscribed
        );
        assert_eq!(server.requests().len(), 4);
    }
}

#[test]
fn lost_renewal_reply_leaves_pending_intent_without_retry_or_recreation() {
    let server = Server::start(|peer| {
        vec![
            renewable_created(peer),
            pulled(0),
            String::new(),
            unsubscribed(),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_renewals = 4;
    let failure = capture_with_progress(&cfg, &cx, renewable_control, |batch| {
        cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
        Ok(receipt(batch.source).into())
    })
    .unwrap_err();
    assert_eq!(failure.report.renewal_intents.len(), 1);
    assert!(failure.report.renewal_outcomes.is_empty());
    assert_eq!(failure.report.renewals, 0);
    assert_eq!(failure.report.pulls, 1);
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(server.requests().len(), 4);
}

#[test]
fn renewal_custody_refusal_blocks_dispatch_or_next_poll_but_allows_live_cleanup() {
    for fail_intent in [true, false] {
        let server = Server::start(|peer| {
            let mut replies = vec![renewable_created(peer), pulled(0)];
            if !fail_intent {
                replies.push(renewed(30));
            }
            replies.push(unsubscribed());
            replies
        });
        let cx = Context::new(server.peer);
        let mut cfg = config(server.peer);
        cfg.max_renewals = 1;
        let failure = capture_with_progress(
            &cfg,
            &cx,
            |event| {
                if matches!(event, PullPointControl::RenewIntent { .. }) && fail_intent
                    || matches!(event, PullPointControl::Renewed { .. }) && !fail_intent
                {
                    Err(MetadataError::Custody)
                } else {
                    renewable_control(event)
                }
            },
            |batch| {
                cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
                Ok(receipt(batch.source).into())
            },
        )
        .unwrap_err();
        assert_eq!(failure.code(), "ERR-ONVIF-METADATA-CUSTODY-001");
        assert_eq!(failure.report.pulls, 1);
        assert_eq!(failure.report.renewals, 0);
        assert!(failure.report.renewal_outcomes.is_empty());
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Unsubscribed
        );
        assert_eq!(server.requests().len(), if fail_intent { 3 } else { 4 });
    }
}

#[test]
fn late_renewal_custody_refusal_preserves_the_successful_receipt_and_count_without_polling() {
    let server = Server::start(|peer| {
        vec![
            renewable_created(peer),
            pulled(0),
            renewed(30),
            unsubscribed(),
        ]
    });
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_renewals = 1;
    let failure = capture_with_progress(
        &cfg,
        &cx,
        |event| {
            let is_renewed = matches!(event, PullPointControl::Renewed { .. });
            let mut progress = renewable_control(event)?;
            if is_renewed {
                progress.stop = Some(PullPointError::Client(ClientError::Budget));
            }
            Ok(progress)
        },
        |batch| {
            cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
            Ok(receipt(batch.source).into())
        },
    )
    .unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-BUDGET-001");
    assert_eq!(failure.report.renewals, 1);
    assert_eq!(failure.report.renewal_outcomes.len(), 1);
    assert_eq!(failure.report.pulls, 1);
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(server.requests().len(), 4);
}

#[test]
fn renewal_intent_custody_cannot_extend_expired_lease_or_override_revocation() {
    for refusal in ["expired", "revoked", "cancelled"] {
        let server = Server::start(|peer| {
            let mut replies = vec![renewable_created(peer), pulled(0)];
            if refusal == "expired" {
                replies.push(unsubscribed());
            }
            replies
        });
        let cx = Context::new(server.peer);
        let mut cfg = config(server.peer);
        cfg.max_renewals = 1;
        let failure = capture_with_progress(
            &cfg,
            &cx,
            |event| {
                if matches!(event, PullPointControl::RenewIntent { .. }) {
                    if refusal == "revoked" {
                        cx.revoked.store(true, Ordering::SeqCst);
                    } else if refusal == "cancelled" {
                        cx.cancelled.store(true, Ordering::SeqCst);
                    } else {
                        cx.offset_ns.fetch_add(2_000_000_000, Ordering::SeqCst);
                    }
                }
                renewable_control(event)
            },
            |batch| {
                cx.offset_ns.fetch_add(600_000_000, Ordering::SeqCst);
                Ok(receipt(batch.source).into())
            },
        )
        .unwrap_err();
        assert_eq!(failure.report.renewal_intents.len(), 1);
        assert!(failure.report.renewal_outcomes.is_empty());
        assert_eq!(failure.report.renewals, 0);
        assert_eq!(
            server.requests().len(),
            if refusal == "expired" { 3 } else { 2 }
        );
        assert_eq!(
            failure.report.subscription_state,
            if refusal == "expired" {
                SubscriptionState::Unsubscribed
            } else {
                SubscriptionState::Active
            }
        );
    }
}

#[test]
fn late_batch_storage_refusal_preserves_receipt_and_counts_then_only_unsubscribes() {
    let server = Server::start(|peer| vec![created(peer), pulled(2), unsubscribed()]);
    let mut retained = None;
    let failure = capture_with_progress(
        &config(server.peer),
        &Context::new(server.peer),
        acknowledged_control,
        |batch| {
            let receipt = receipt(batch.source);
            retained = Some(receipt);
            Ok(RetainedProgress {
                receipt,
                stop: Some(PullPointError::Client(ClientError::Budget)),
            })
        },
    )
    .unwrap_err();
    assert!(matches!(
        failure.error,
        PullPointError::Client(ClientError::Budget)
    ));
    assert_eq!(failure.report.retained, vec![retained.unwrap()]);
    assert_eq!(failure.report.pulls, 1);
    assert_eq!(failure.report.notifications, 2);
    assert!(failure.report.create_intent.is_some());
    assert!(failure.report.created_subscription.is_some());
    assert!(failure.report.unsubscribe_receipt.is_some());
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert!(failure.report.cleanup_error.is_none());
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].contains("PullMessages"));
    assert!(requests[2].contains("Unsubscribe"));
    assert!(!requests[2].contains("PullMessages"));
}

#[test]
fn late_intent_storage_refusal_keeps_receipt_without_admitting_create() {
    let server = Server::start(|_| vec![String::new()]);
    let cx = Context::new(server.peer);
    let intent_receipt = receipt(b"fixture:create-intent");
    let failure = capture_with_progress(
        &config(server.peer),
        &cx,
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Ok(RetainedProgress {
                receipt: intent_receipt,
                stop: Some(PullPointError::Client(ClientError::Budget)),
            }),
            _ => panic!("late intent refusal cannot admit Create"),
        },
        |_| panic!("no poll is admitted"),
    )
    .unwrap_err();
    assert!(matches!(
        failure.error,
        PullPointError::Client(ClientError::Budget)
    ));
    assert_eq!(failure.report.create_intent, Some(intent_receipt));
    assert!(failure.report.created_subscription.is_none());
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::NotCreated
    );
    assert_eq!(failure.report.exchanges, 0);
    assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
    assert!(server.requests().is_empty());
}

#[test]
fn cleanup_only_uses_retained_epr_and_fresh_id_without_create_or_poll() {
    let server = Server::start(|_| vec![unsubscribed()]);
    let cx = Context::new(server.peer);
    let create_id = "urn:fixture:retained-create";
    let source = created(server.peer).replace("REQUEST_ID", create_id);
    let subscription =
        parse_pull_point_subscription(source.strip_prefix("SOAP:").unwrap().as_bytes()).unwrap();
    let request_digest = std::cell::Cell::new(None);
    let report = unsubscribe_existing(
        &config(server.peer),
        &cx,
        &subscription,
        create_id,
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::UnsubscribeIntent {
                message_id,
                create_message_id,
                request_digest: actual_request,
                ..
            } => {
                assert_eq!(create_message_id, create_id);
                assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
                request_digest.set(Some(actual_request));
                Ok(receipt(message_id.as_bytes()).into())
            }
            PullPointControl::UnsubscribeOutcome { source, .. } => Ok(receipt(source).into()),
            PullPointControl::Unsubscribed {
                route,
                source,
                message_id,
                started_ns,
                completed_ns,
                authenticated,
            } => {
                assert_eq!(route.target(), SUBSCRIPTION);
                assert_ne!(message_id, create_id);
                assert!(started_ns <= completed_ns);
                assert!(!authenticated);
                assert!(
                    std::str::from_utf8(source)
                        .unwrap()
                        .contains("UnsubscribeResponse")
                );
                Ok(receipt(source).into())
            }
            _ => panic!("cleanup-only cannot create or poll"),
        },
    )
    .unwrap();
    assert_eq!(report.stop, CaptureStop::CleanupOnly);
    assert_eq!(report.subscription_state, SubscriptionState::Unsubscribed);
    assert_eq!(report.pulls, 0);
    assert!(report.retained.is_empty());
    assert!(report.unsubscribe_receipt.is_some());
    assert!(report.unsubscribe_intent.is_some());
    assert!(report.unsubscribe_outcome.is_some());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("Unsubscribe"));
    assert!(requests[0].contains("exact-opaque"));
    assert!(requests[0].contains("IsReferenceParameter"));
    assert!(!requests[0].contains("CreatePullPointSubscription"));
    assert!(!requests[0].contains("PullMessages"));
    let request_body = requests[0].split_once("\r\n\r\n").unwrap().1;
    assert_eq!(
        request_digest.get(),
        Some(ContentDigest::sha256(request_body.as_bytes()))
    );
}

fn cleanup_fixture(peer: SocketAddr) -> fss_reference::onvif::wire::PullPointSubscription {
    let source = created(peer).replace("REQUEST_ID", "urn:fixture:retained-create");
    parse_pull_point_subscription(source.strip_prefix("SOAP:").unwrap().as_bytes()).unwrap()
}

#[test]
fn cleanup_intent_custody_or_replay_refusal_precedes_every_connection() {
    for refused_after_receipt in [false, true] {
        let server = Server::start(|_| vec![unsubscribed()]);
        let cx = Context::new(server.peer);
        let expected = receipt(b"fixture:cleanup-intent");
        let failure = unsubscribe_existing(
            &config(server.peer),
            &cx,
            &cleanup_fixture(server.peer),
            "urn:fixture:retained-create",
            |event| match event {
                PullPointControl::UnsubscribeIntent { .. } if refused_after_receipt => {
                    Ok(RetainedProgress {
                        receipt: expected,
                        // A previously prepared intent returns its handle plus refusal to resend.
                        stop: Some(PullPointError::Retention(MetadataError::Authority)),
                    })
                }
                PullPointControl::UnsubscribeIntent { .. } => Err(MetadataError::Custody),
                _ => panic!("unadmitted cleanup cannot receive a response"),
            },
        )
        .unwrap_err();
        assert_eq!(
            failure.report.unsubscribe_intent,
            refused_after_receipt.then_some(expected)
        );
        assert!(failure.report.unsubscribe_outcome.is_none());
        assert!(failure.report.unsubscribe_receipt.is_none());
        assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
        assert_eq!(failure.report.exchanges, 0);
        assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
        assert!(server.requests().is_empty());
    }
}

#[test]
fn capture_cleanup_intent_failure_keeps_batches_without_dispatching_unsubscribe() {
    let server = Server::start(|peer| vec![created(peer), pulled(1)]);
    let cx = Context::new(server.peer);
    let mut cfg = config(server.peer);
    cfg.max_pulls = 1;
    let failure = capture_with_progress(
        &cfg,
        &cx,
        |event| match event {
            PullPointControl::UnsubscribeIntent { .. } => Err(MetadataError::Custody),
            PullPointControl::UnsubscribeOutcome { .. } | PullPointControl::Unsubscribed { .. } => {
                panic!("cleanup was never dispatched")
            }
            event => acknowledged_control(event),
        },
        |batch| Ok(receipt(batch.source).into()),
    )
    .unwrap_err();
    assert_eq!(failure.code(), MetadataError::Custody.code());
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert!(failure.report.unsubscribe_intent.is_none());
    assert!(failure.report.unsubscribe_outcome.is_none());
    assert_eq!(server.requests().len(), 2);
    assert_eq!(cx.connects.load(Ordering::SeqCst), 2);
}

#[test]
fn malformed_status_or_uncorrelated_cleanup_is_retained_before_refusal() {
    for variant in 0..4 {
        let server = Server::start(|_| {
            vec![match variant {
                0 => soap("<wsnt:WrongResponse/>", "REQUEST_ID"),
                1 => unsubscribed().replace("REQUEST_ID", "urn:fixture:other-request"),
                2 => unsubscribed().replace("<a:RelatesTo>REQUEST_ID</a:RelatesTo>", ""),
                _ => "HTTP/1.1 503 Unavailable\r\nContent-Length: 10\r\n\r\nraw-failed".into(),
            }]
        });
        let mut observed = None;
        let failure = unsubscribe_existing(
            &config(server.peer),
            &Context::new(server.peer),
            &cleanup_fixture(server.peer),
            "urn:fixture:retained-create",
            |event| match event {
                PullPointControl::UnsubscribeIntent { message_id, .. } => {
                    Ok(receipt(message_id.as_bytes()).into())
                }
                PullPointControl::UnsubscribeOutcome {
                    source,
                    completed_ns,
                    http_status,
                    soap_content_type,
                    ..
                } => {
                    assert!(completed_ns.is_some());
                    assert_eq!(server.requests().len(), 1);
                    assert_eq!(http_status, if variant == 3 { 503 } else { 200 });
                    assert_eq!(soap_content_type, variant != 3);
                    let retained = receipt(source);
                    observed = Some(retained);
                    Ok(retained.into())
                }
                _ => panic!("an invalid response cannot produce terminal custody"),
            },
        )
        .unwrap_err();
        assert!(failure.report.unsubscribe_intent.is_some());
        assert!(observed.is_some());
        assert_eq!(failure.report.unsubscribe_outcome, observed);
        assert!(failure.report.unsubscribe_receipt.is_none());
        assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn complete_terminal_cleanup_auth_refusal_reaches_raw_custody() {
    for retry in [false, true] {
        let server = Server::start(|_| {
            let mut replies = vec![challenge(REALM)];
            if retry {
                replies.push(challenge(REALM));
            }
            replies
        });
        let mut cfg = config(server.peer);
        if retry {
            cfg.auth = Some(DigestConfig {
                expected_realm: REALM.into(),
                policy: DigestPolicy::default(),
            });
        }
        let failure = unsubscribe_existing(
            &cfg,
            &Context::new(server.peer),
            &cleanup_fixture(server.peer),
            "urn:fixture:retained-create",
            |event| match event {
                PullPointControl::UnsubscribeIntent { message_id, .. } => {
                    Ok(receipt(message_id.as_bytes()).into())
                }
                PullPointControl::UnsubscribeOutcome {
                    source,
                    authenticated,
                    http_status,
                    completed_ns,
                    ..
                } => {
                    assert!(source.is_empty());
                    assert_eq!(http_status, 401);
                    assert_eq!(authenticated, retry);
                    assert!(completed_ns.is_some());
                    Ok(receipt(source).into())
                }
                _ => panic!("authentication refusal cannot confirm cleanup"),
            },
        )
        .unwrap_err();
        assert_eq!(failure.report.unsubscribe_outcome, Some(receipt(b"")));
        assert!(failure.report.unsubscribe_receipt.is_none());
        assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
        let requests = server.requests();
        assert_eq!(requests.len(), if retry { 2 } else { 1 });
        if retry {
            assert_eq!(message_id(&requests[0]), message_id(&requests[1]));
        }
    }
}

#[test]
fn lost_cleanup_reply_preserves_intent_without_retry_create_or_renew() {
    let server = Server::start(|_| vec![String::new()]);
    let mut cfg = config(server.peer);
    cfg.max_renewals = 1;
    let failure = unsubscribe_existing(
        &cfg,
        &Context::new(server.peer),
        &cleanup_fixture(server.peer),
        "urn:fixture:retained-create",
        |event| match event {
            PullPointControl::UnsubscribeIntent { message_id, .. } => {
                Ok(receipt(message_id.as_bytes()).into())
            }
            _ => panic!("lost response cannot create a response receipt"),
        },
    )
    .unwrap_err();
    assert!(failure.report.unsubscribe_intent.is_some());
    assert!(failure.report.unsubscribe_outcome.is_none());
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("Unsubscribe"));
    for operation in [
        "CreatePullPointSubscription",
        "PullMessages",
        "<wsnt:Renew>",
    ] {
        assert!(!requests[0].contains(operation));
    }
}

#[test]
fn complete_cleanup_outcome_survives_custody_stop_and_late_live_refusal() {
    for variant in 0..4 {
        let server = Server::start(|_| vec![unsubscribed()]);
        let cx = Context::new(server.peer);
        let mut observed = None;
        let failure = unsubscribe_existing(
            &config(server.peer),
            &cx,
            &cleanup_fixture(server.peer),
            "urn:fixture:retained-create",
            |event| match event {
                PullPointControl::UnsubscribeIntent { message_id, .. } => {
                    Ok(receipt(message_id.as_bytes()).into())
                }
                PullPointControl::UnsubscribeOutcome { source, .. } => {
                    if variant == 0 {
                        return Err(MetadataError::Custody);
                    }
                    let retained = receipt(source);
                    observed = Some(retained);
                    if variant == 2 {
                        cx.cancelled.store(true, Ordering::SeqCst);
                    }
                    if variant == 3 {
                        cx.revoked.store(true, Ordering::SeqCst);
                    }
                    Ok(RetainedProgress {
                        receipt: retained,
                        stop: (variant == 1).then_some(PullPointError::Client(ClientError::Budget)),
                    })
                }
                _ => panic!("outcome refusal prevents the later terminal callback"),
            },
        )
        .unwrap_err();
        assert_eq!(
            failure.report.subscription_state,
            SubscriptionState::Unsubscribed
        );
        assert_eq!(failure.report.unsubscribe_outcome, observed);
        assert!(failure.report.unsubscribe_intent.is_some());
        assert!(failure.report.unsubscribe_receipt.is_none());
        assert!(failure.report.cleanup_error.is_some());
        assert_eq!(server.requests().len(), 1);
    }
}

#[test]
fn cleanup_intent_cannot_override_late_cancellation_revocation_or_deadline() {
    for variant in 0..3 {
        let server = Server::start(|_| vec![unsubscribed()]);
        let cx = Context::new(server.peer);
        let failure = unsubscribe_existing(
            &config(server.peer),
            &cx,
            &cleanup_fixture(server.peer),
            "urn:fixture:retained-create",
            |event| match event {
                PullPointControl::UnsubscribeIntent { message_id, .. } => {
                    match variant {
                        0 => cx.cancelled.store(true, Ordering::SeqCst),
                        1 => cx.revoked.store(true, Ordering::SeqCst),
                        _ => cx.offset_ns.store(8_000_000_000, Ordering::SeqCst),
                    }
                    Ok(receipt(message_id.as_bytes()).into())
                }
                _ => panic!("live authority refusal prevents every connection"),
            },
        )
        .unwrap_err();
        assert!(failure.report.unsubscribe_intent.is_some());
        assert!(failure.report.unsubscribe_outcome.is_none());
        assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
        assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
        assert!(server.requests().is_empty());
    }
}

#[test]
fn released_cleanup_source_and_completion_survive_immediate_clock_cancellation() {
    let server = Server::start(|_| vec![unsubscribed()]);
    let mut cx = Context::new(server.peer);
    cx.cancel_on_subscription_release = true;
    let mut completed = None;
    let failure = unsubscribe_existing(
        &config(server.peer),
        &cx,
        &cleanup_fixture(server.peer),
        "urn:fixture:retained-create",
        |event| match event {
            PullPointControl::UnsubscribeIntent { message_id, .. } => {
                Ok(receipt(message_id.as_bytes()).into())
            }
            PullPointControl::UnsubscribeOutcome {
                source,
                completed_ns,
                ..
            } => {
                assert!(cx.cancelled.load(Ordering::SeqCst));
                completed = completed_ns;
                Ok(receipt(source).into())
            }
            _ => panic!("cancelled owner cannot publish the final marker"),
        },
    )
    .unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-CANCELLED-001");
    assert!(completed.is_some());
    assert!(failure.report.unsubscribe_outcome.is_some());
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn cleanup_only_rejects_original_create_id_reuse_before_any_connection() {
    let server = Server::start(|_| vec![String::new()]);
    let cx = Context::new(server.peer);
    let create_id = format!("urn:fss:onvif:{}", "01".repeat(16));
    let source = created(server.peer).replace("REQUEST_ID", &create_id);
    let subscription =
        parse_pull_point_subscription(source.strip_prefix("SOAP:").unwrap().as_bytes()).unwrap();
    let failure =
        unsubscribe_existing(&config(server.peer), &cx, &subscription, &create_id, |_| {
            panic!("reused request identity cannot dispatch")
        })
        .unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-ENTROPY-001");
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert_eq!(failure.report.exchanges, 0);
    assert_eq!(cx.connects.load(Ordering::SeqCst), 0);
    assert!(server.requests().is_empty());
}

#[test]
fn terminal_custody_refusal_preserves_observed_cleanup_and_all_earlier_receipts() {
    let server = Server::start(|peer| vec![created(peer), pulled(1), unsubscribed()]);
    let mut cfg = config(server.peer);
    cfg.max_pulls = 1;
    let failure = capture_with_control(
        &cfg,
        &Context::new(server.peer),
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Ok(receipt(b"fixture:create-intent")),
            PullPointControl::UnsubscribeIntent { message_id, .. } => {
                Ok(receipt(message_id.as_bytes()))
            }
            PullPointControl::CreateOutcome { source, .. }
            | PullPointControl::Created { source, .. } => Ok(receipt(source)),
            PullPointControl::UnsubscribeOutcome { source, .. } => Ok(receipt(source)),
            PullPointControl::Unsubscribed { .. } => Err(MetadataError::Custody),
        },
        |batch| Ok(receipt(batch.source)),
    )
    .unwrap_err();
    assert_eq!(failure.code(), "ERR-ONVIF-METADATA-CUSTODY-001");
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Unsubscribed
    );
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.pulls, 1);
    assert_eq!(failure.report.notifications, 1);
    assert!(failure.report.create_intent.is_some());
    assert!(failure.report.created_subscription.is_some());
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert_eq!(
        failure.report.cleanup_error,
        Some("ERR-ONVIF-METADATA-CUSTODY-001")
    );
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn cleanup_without_explicit_correlation_cannot_claim_remote_success_or_terminal_custody() {
    let server = Server::start(|peer| {
        vec![
            created(peer),
            pulled(0),
            unsubscribed().replace("<a:RelatesTo>REQUEST_ID</a:RelatesTo>", ""),
        ]
    });
    let mut cfg = config(server.peer);
    cfg.max_pulls = 1;
    let failure = capture_with_control(
        &cfg,
        &Context::new(server.peer),
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Ok(receipt(b"fixture:create-intent")),
            PullPointControl::UnsubscribeIntent { message_id, .. } => {
                Ok(receipt(message_id.as_bytes()))
            }
            PullPointControl::CreateOutcome { source, .. }
            | PullPointControl::Created { source, .. } => Ok(receipt(source)),
            PullPointControl::UnsubscribeOutcome { source, .. } => Ok(receipt(source)),
            PullPointControl::Unsubscribed { .. } => {
                panic!("uncorrelated cleanup cannot reach terminal custody")
            }
        },
        |batch| Ok(receipt(batch.source)),
    )
    .unwrap_err();
    assert_eq!(failure.report.subscription_state, SubscriptionState::Active);
    assert!(failure.report.cleanup_error.is_some());
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert!(failure.report.create_intent.is_some());
    assert!(failure.report.created_subscription.is_some());
    assert_eq!(failure.report.retained.len(), 1);
    assert_eq!(failure.report.pulls, 1);
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn create_without_explicit_correlation_keeps_intent_without_following_an_unbound_epr() {
    let server = Server::start(|peer| {
        vec![created(peer).replace("<a:RelatesTo>REQUEST_ID</a:RelatesTo>", "")]
    });
    let intent_receipt = receipt(b"fixture:create-intent");
    let failure = capture_with_control(
        &config(server.peer),
        &Context::new(server.peer),
        |event| match event {
            PullPointControl::RenewIntent { .. } | PullPointControl::Renewed { .. } => {
                panic!("renewal disabled in this fixture")
            }
            PullPointControl::CreateIntent { .. } => Ok(intent_receipt),
            PullPointControl::CreateOutcome { .. }
            | PullPointControl::Created { .. }
            | PullPointControl::Unsubscribed { .. }
            | PullPointControl::UnsubscribeIntent { .. }
            | PullPointControl::UnsubscribeOutcome { .. } => {
                panic!("an uncorrelated Create response cannot admit EPR custody or cleanup")
            }
        },
        |_| panic!("an uncorrelated EPR cannot admit a poll"),
    )
    .unwrap_err();
    assert_eq!(
        failure.report.subscription_state,
        SubscriptionState::Indeterminate
    );
    assert_eq!(failure.report.create_intent, Some(intent_receipt));
    assert!(failure.report.created_subscription.is_none());
    assert!(failure.report.unsubscribe_receipt.is_none());
    assert!(failure.report.subscription_response().is_some());
    assert!(failure.report.retained.is_empty());
    assert_eq!(failure.report.pulls, 0);
    assert!(failure.report.cleanup_error.is_none());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("CreatePullPointSubscription"));
}
