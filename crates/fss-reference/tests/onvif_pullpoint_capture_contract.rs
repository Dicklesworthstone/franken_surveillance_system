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
    CaptureStop, PullPointConfig, PullPointError, RetainedBatch, SubscriptionState, capture,
    route_in_service_root, validate_config,
};
use fss_reference::onvif::wire::{create_pull_point_request, get_profiles_request};
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
    ids: AtomicU32,
    repeat_ids: bool,
    cancel_on_create_release: bool,
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
            ids: AtomicU32::new(0),
            repeat_ids: false,
            cancel_on_create_release: false,
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
        if self.cancel_on_create_release
            && operation == HttpOperation::Release
            && route.target() == "/onvif/events"
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
    assert!(failure.report.subscription_completed_ns().is_none());
    assert_eq!(server.requests().len(), 1);
}
