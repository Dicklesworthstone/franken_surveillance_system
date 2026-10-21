//! Real loopback proof of the explicit WSSE lane and credential/clock fences.

use std::cell::{Cell, RefCell};

use super::*;
use fss_reference::onvif::authentication::{UsernameToken, UtcDateTime};
use fss_reference::onvif::http::HttpError;
use fss_reference::onvif::wire::{OnvifOperation, SoapRequest};

const TIME: &str = "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:UTCDateTime><tt:Time><tt:Hour>23</tt:Hour><tt:Minute>59</tt:Minute><tt:Second>59</tt:Second></tt:Time><tt:Date><tt:Year>2024</tt:Year><tt:Month>2</tt:Month><tt:Day>29</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    WrongCreated,
    RegressClock,
    Expire,
    Revoke,
    CredentialsAtSecondRequest,
    Entropy,
}

struct TokenContext {
    base: Context,
    clock: Cell<u64>,
    timestamps: RefCell<Vec<UtcDateTime>>,
    revoked: Cell<bool>,
    fault: Fault,
}

impl TokenContext {
    fn new(peer: SocketAddr, fault: Fault) -> Self {
        Self {
            base: Context::new(peer),
            clock: Cell::new(1),
            timestamps: RefCell::new(Vec::new()),
            revoked: Cell::new(false),
            fault,
        }
    }
}

impl HttpAuthority for TokenContext {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        operation: HttpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpDenial> {
        if self.revoked.get() {
            return Err(HttpDenial::Revoked);
        }
        self.base.checkpoint(route, operation, now, deadline)
    }
}

impl OnvifContext for TokenContext {
    fn now_ns(&self) -> Result<u64, ClientError> {
        self.base.now_ns()?;
        Ok(self.clock.get())
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        self.base.wait(deadline_ns)
    }
    fn authorize(
        &self,
        route: &HttpRoute,
        challenge: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        self.base.authorize(route, challenge)
    }
    fn username_token(
        &self,
        route: &HttpRoute,
        request: &SoapRequest,
        created: UtcDateTime,
    ) -> Result<UsernameToken, ClientError> {
        assert_eq!(route.peer(), self.base.peer);
        assert!(!request.has_username_token());
        assert_ne!(
            request.action(),
            OnvifOperation::GetSystemDateAndTime.action()
        );
        self.timestamps.borrow_mut().push(created);
        let count = self.timestamps.borrow().len();
        if self.fault == Fault::CredentialsAtSecondRequest && count == 2 {
            return Err(ClientError::Credentials);
        }
        if self.fault == Fault::Entropy {
            return Err(ClientError::Entropy);
        }
        let credentials = DigestCredentials::new("fixture-user", "fixture-password")?;
        let token = UsernameToken::new(
            &credentials,
            [u8::try_from(count).unwrap(); 16],
            if self.fault == Fault::WrongCreated {
                created.checked_add_seconds(1)?
            } else {
                created
            },
        );
        match self.fault {
            Fault::RegressClock => self.clock.set(0),
            Fault::Expire => self.clock.set(12_000_000_000),
            _ => self.clock.set(self.clock.get() + 2_000_000_000),
        }
        if self.fault == Fault::Revoke {
            self.revoked.set(true);
        }
        Ok(token)
    }
}

fn token_config(peer: SocketAddr, media_version: MediaVersion) -> ClientConfig {
    ClientConfig {
        media_version,
        auth: Some(AuthenticationConfig::UsernameTokenDigest),
        deadline_ns: 12_000_000_000,
        ..config(peer)
    }
}

fn successful_replies(
    peer: SocketAddr,
    media_version: MediaVersion,
    selected: bool,
) -> Vec<String> {
    let mut replies = vec![ok(soap(TIME))];
    match media_version {
        MediaVersion::Media1 => {
            replies.push(capabilities(&format!("http://{peer}/onvif/media_service")));
            replies.push(profiles());
            if selected {
                replies.push(stream(STREAM));
            }
        }
        MediaVersion::Media2 => {
            replies.push(media2_services(&format!(
                "http://{peer}/onvif/media2_service"
            )));
            replies.push(media2_profiles(true));
            if selected {
                replies.push(media2_stream(STREAM));
            }
        }
    }
    replies
}

#[test]
fn media1_and_media2_use_one_unsigned_time_read_and_fresh_monotonic_advanced_tokens() {
    for version in [MediaVersion::Media1, MediaVersion::Media2] {
        let server = Server::start(|peer| successful_replies(peer, version, true));
        let cx = TokenContext::new(server.peer, Fault::None);
        let result = run(&token_config(server.peer, version), Some(TOKEN), &cx).unwrap();
        assert_eq!(result.exchanges, 4);
        assert_eq!(result.discovery.media_version(), version);
        assert_eq!(result.selection.unwrap().stream.uri, STREAM);
        assert_eq!(cx.base.auth_calls.load(Ordering::SeqCst), 0);
        let expected_created = [
            "2024-02-29T23:59:59Z",
            "2024-03-01T00:00:01Z",
            "2024-03-01T00:00:03Z",
        ];
        assert_eq!(
            cx.timestamps
                .borrow()
                .iter()
                .map(|time| time.to_rfc3339())
                .collect::<Vec<_>>(),
            expected_created
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with("POST /onvif/device_service HTTP/1.1\r\n"));
        assert!(requests[0].contains("<tds:GetSystemDateAndTime/>"));
        assert!(!requests[0].contains("wsse:"));
        let expected_nonce = [
            "AQEBAQEBAQEBAQEBAQEBAQ==",
            "AgICAgICAgICAgICAgICAg==",
            "AwMDAwMDAwMDAwMDAwMDAw==",
        ];
        for (index, request) in requests.iter().skip(1).enumerate() {
            assert!(request.contains(&format!(
                "<wsu:Created>{}</wsu:Created>",
                expected_created[index]
            )));
            assert!(request.contains(&format!(
                "#Base64Binary\">{}</wsse:Nonce>",
                expected_nonce[index]
            )));
            assert_eq!(request.matches("<wsse:UsernameToken>").count(), 1);
            assert!(!request.contains("GetSystemDateAndTime"));
        }
        for request in requests {
            assert!(!request.contains("Authorization:"));
            assert!(!request.contains("fixture-password"));
        }
    }
}

#[test]
fn inventory_remains_bounded_and_does_not_request_a_stream_uri() {
    for version in [MediaVersion::Media1, MediaVersion::Media2] {
        let server = Server::start(|peer| successful_replies(peer, version, false));
        let cx = TokenContext::new(server.peer, Fault::None);
        let result = run(&token_config(server.peer, version), None, &cx).unwrap();
        assert_eq!(result.exchanges, 3);
        assert!(result.selection.is_none());
        assert_eq!(cx.timestamps.borrow().len(), 2);
        assert!(
            server
                .requests()
                .iter()
                .all(|request| !request.contains("GetStreamUri"))
        );
    }
}

#[test]
fn bootstrap_or_signed_401_never_changes_authentication_mechanism_or_retries() {
    for signed in [false, true] {
        let server = Server::start(|_| {
            if signed {
                vec![ok(soap(TIME)), challenge(REALM)]
            } else {
                vec![challenge(REALM)]
            }
        });
        let cx = TokenContext::new(server.peer, Fault::None);
        assert!(matches!(
            run(&token_config(server.peer, MediaVersion::Media1), None, &cx),
            Err(ClientError::AuthenticationRefused)
        ));
        assert_eq!(server.requests().len(), if signed { 2 } else { 1 });
        assert_eq!(cx.timestamps.borrow().len(), usize::from(signed));
        assert_eq!(cx.base.auth_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn soap_authorization_fault_does_not_trigger_a_time_probe_or_mechanism_fallback() {
    let fault = soap(
        "<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value xmlns:ter=\"http://www.onvif.org/ver10/error\">ter:NotAuthorized</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang=\"en\">private remote reason</s:Text></s:Reason></s:Fault>",
    );
    for wsse in [false, true] {
        let server = Server::start(|_| {
            let response = ok(fault.clone()).replace("200 OK", "500 Internal Server Error");
            if wsse {
                vec![ok(soap(TIME)), response]
            } else {
                vec![response]
            }
        });
        let cx = TokenContext::new(server.peer, Fault::None);
        let cfg = if wsse {
            token_config(server.peer, MediaVersion::Media1)
        } else {
            config(server.peer)
        };
        let error = run(&cfg, None, &cx).unwrap_err();
        assert!(matches!(error, ClientError::Wire(WireError::SoapFault(_))));
        assert!(!format!("{error:?}").contains("private remote reason"));
        assert_eq!(cx.timestamps.borrow().len(), usize::from(wsse));
        assert_eq!(server.requests().len(), if wsse { 2 } else { 1 });
        assert_eq!(cx.base.auth_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn created_binding_clock_deadline_revocation_and_entropy_fence_before_signed_io() {
    for fault in [
        Fault::WrongCreated,
        Fault::RegressClock,
        Fault::Expire,
        Fault::Revoke,
        Fault::Entropy,
    ] {
        let server = Server::start(|_| vec![ok(soap(TIME))]);
        let cx = TokenContext::new(server.peer, fault);
        let error = run(&token_config(server.peer, MediaVersion::Media1), None, &cx).unwrap_err();
        assert!(matches!(
            (fault, error),
            (Fault::WrongCreated, ClientError::Credentials)
                | (Fault::RegressClock, ClientError::Clock)
                | (Fault::Expire, ClientError::Deadline)
                | (
                    Fault::Revoke,
                    ClientError::Http(HttpError::Denied(HttpDenial::Revoked))
                )
                | (Fault::Entropy, ClientError::Entropy)
        ));
        assert_eq!(server.requests().len(), 1);
        assert_eq!(cx.timestamps.borrow().len(), 1);
        assert_eq!(cx.base.auth_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn credentials_are_revalidated_for_each_operation_and_old_owners_deny_by_default() {
    let server = Server::start(|peer| {
        vec![
            ok(soap(TIME)),
            capabilities(&format!("http://{peer}/onvif/media_service")),
        ]
    });
    let cx = TokenContext::new(server.peer, Fault::CredentialsAtSecondRequest);
    assert!(matches!(
        run(
            &token_config(server.peer, MediaVersion::Media1),
            Some(TOKEN),
            &cx
        ),
        Err(ClientError::Credentials)
    ));
    assert_eq!(server.requests().len(), 2);
    assert_eq!(cx.timestamps.borrow().len(), 2);
    let server = Server::start(|_| vec![ok(soap(TIME))]);
    let cx = Context::new(server.peer);
    assert!(matches!(
        run(&token_config(server.peer, MediaVersion::Media1), None, &cx),
        Err(ClientError::Credentials)
    ));
    assert_eq!(server.requests().len(), 1);
    assert_eq!(cx.auth_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn advertised_foreign_or_outside_subtree_route_never_receives_a_token() {
    for version in [MediaVersion::Media1, MediaVersion::Media2] {
        for foreign in [false, true] {
            let server = Server::start(|peer| {
                let uri = if foreign {
                    "http://127.0.0.2:80/onvif/media_service".to_owned()
                } else {
                    format!("http://{peer}/private/media_service")
                };
                vec![
                    ok(soap(TIME)),
                    match version {
                        MediaVersion::Media1 => capabilities(&uri),
                        MediaVersion::Media2 => media2_services(&uri),
                    },
                ]
            });
            let cx = TokenContext::new(server.peer, Fault::None);
            assert!(matches!(
                run(&token_config(server.peer, version), None, &cx),
                Err(ClientError::Scope)
            ));
            assert_eq!(cx.timestamps.borrow().len(), 1);
            assert_eq!(server.requests().len(), 2);
            assert_eq!(cx.base.auth_calls.load(Ordering::SeqCst), 0);
        }
    }
}

struct CheckpointContext {
    inner: TokenContext,
    releases: Cell<u32>,
    operation: HttpOperation,
    denial: HttpDenial,
}

impl HttpAuthority for CheckpointContext {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        operation: HttpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpDenial> {
        if operation == HttpOperation::Release {
            self.releases.set(self.releases.get() + 1);
        }
        // First release belongs to HTTP response ownership; the second is the
        // core's parsed UTC release. Subsequent Write is the pre-token boundary.
        if self.releases.get() >= 2 && operation == self.operation {
            return Err(self.denial);
        }
        self.inner.checkpoint(route, operation, now, deadline)
    }
}

impl OnvifContext for CheckpointContext {
    fn now_ns(&self) -> Result<u64, ClientError> {
        self.inner.now_ns()
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        self.inner.wait(deadline_ns)
    }
    fn authorize(
        &self,
        route: &HttpRoute,
        challenge: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        self.inner.authorize(route, challenge)
    }
    fn username_token(
        &self,
        route: &HttpRoute,
        request: &SoapRequest,
        created: UtcDateTime,
    ) -> Result<UsernameToken, ClientError> {
        self.inner.username_token(route, request, created)
    }
}

#[test]
fn bootstrap_release_and_pre_token_checkpoints_preserve_control_flow_denials() {
    for operation in [HttpOperation::Release, HttpOperation::Write] {
        for denial in [
            HttpDenial::Cancelled,
            HttpDenial::Deadline,
            HttpDenial::Budget,
            HttpDenial::Unauthorized,
            HttpDenial::Revoked,
        ] {
            let server = Server::start(|_| vec![ok(soap(TIME))]);
            let cx = CheckpointContext {
                inner: TokenContext::new(server.peer, Fault::None),
                releases: Cell::new(0),
                operation,
                denial,
            };
            let error =
                run(&token_config(server.peer, MediaVersion::Media1), None, &cx).unwrap_err();
            assert!(matches!(
                (denial, error),
                (HttpDenial::Cancelled, ClientError::Cancelled)
                    | (HttpDenial::Deadline, ClientError::Deadline)
                    | (HttpDenial::Budget, ClientError::Budget)
                    | (
                        HttpDenial::Unauthorized | HttpDenial::Revoked,
                        ClientError::Authority
                    )
            ));
            assert_eq!(cx.releases.get(), 2);
            assert!(cx.inner.timestamps.borrow().is_empty());
            assert_eq!(cx.inner.base.auth_calls.load(Ordering::SeqCst), 0);
            assert_eq!(server.requests().len(), 1);
        }
    }
}
