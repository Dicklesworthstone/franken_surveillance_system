#![forbid(unsafe_code)]
//! Real native loopback contracts for scoped snapshot acquisition and source custody.

use fss_core::ContentDigest;
use fss_reference::onvif::client::{ClientError, OnvifContext};
use fss_reference::onvif::http::{HttpAuthority, HttpDenial, HttpOperation, HttpRoute};
use fss_reference::onvif::snapshot::{self, Snapshot, SnapshotPlan};
use fss_reference::rtsp::authentication::{DigestAuthorization, DigestChallenge};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const JPEG: &[u8] = include_bytes!("../../fss-cli/tests/fixtures/retained_file_8x8.jpg");
const PROFILES: &str = concat!(
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><trt:GetProfilesResponse>",
    "<trt:Profiles token=\"video\"><tt:Name>Private camera name</tt:Name><tt:VideoEncoderConfiguration><tt:Encoding>JPEG</tt:Encoding><tt:Resolution><tt:Width>8</tt:Width><tt:Height>8</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>",
    "</trt:GetProfilesResponse></s:Body></s:Envelope>"
);

struct Owner {
    start: Instant,
    media: HttpRoute,
    cancelled_read: bool,
    authorizations: Cell<u32>,
}

impl HttpAuthority for Owner {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        operation: HttpOperation,
        _: u64,
        deadline_ns: u64,
    ) -> Result<(), HttpDenial> {
        if self.start.elapsed().as_nanos() >= u128::from(deadline_ns) {
            return Err(HttpDenial::Deadline);
        }
        if route.peer() != self.media.peer()
            || route.authority() != self.media.authority()
            || route.generation() != self.media.generation()
            || route.plaintext_approval() != self.media.plaintext_approval()
        {
            return Err(HttpDenial::Unauthorized);
        }
        if self.cancelled_read
            && operation == HttpOperation::Read
            && route.target().starts_with("/snapshot")
        {
            return Err(HttpDenial::Cancelled);
        }
        Ok(())
    }
}

impl OnvifContext for Owner {
    fn now_ns(&self) -> Result<u64, ClientError> {
        Ok(self.start.elapsed().as_nanos() as u64)
    }
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError> {
        if self.now_ns()? >= deadline_ns {
            return Err(ClientError::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
        if self.now_ns()? >= deadline_ns {
            return Err(ClientError::Deadline);
        }
        Ok(())
    }
    fn authorize(
        &self,
        _: &HttpRoute,
        _: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError> {
        self.authorizations.set(self.authorizations.get() + 1);
        Err(ClientError::Credentials)
    }
}

struct Case {
    body: Vec<u8>,
    chunked: bool,
    other_origin: bool,
    first_status: u16,
    cancel: bool,
    delay: Duration,
    deadline_ns: u64,
    max_bytes: usize,
}

impl Default for Case {
    fn default() -> Self {
        Self {
            body: JPEG.to_vec(),
            chunked: false,
            other_origin: false,
            first_status: 200,
            cancel: false,
            delay: Duration::ZERO,
            deadline_ns: 2_000_000_000,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

fn request(stream: &mut TcpStream) -> Test<String> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    loop {
        if bytes.len() > 65536 {
            return Err("request limit".into());
        }
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..end])?;
            let content_length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .map(str::parse::<usize>)
                .transpose()?
                .unwrap_or(0);
            if bytes.len() >= end + 4 + content_length {
                return Ok(String::from_utf8(bytes)?);
            }
        }
        let mut buffer = [0; 2048];
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err("early request EOF".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn serve(listener: TcpListener, case: &Case) -> Test<Vec<String>> {
    listener.set_nonblocking(true)?;
    let count = if case.first_status != 200 {
        1
    } else if case.other_origin {
        2
    } else {
        3
    };
    let until = Instant::now() + Duration::from_secs(3);
    let mut requests = Vec::new();
    for index in 0..count {
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error.into()),
            }
        };
        requests.push(request(&mut stream)?);
        let port = if case.other_origin {
            1
        } else {
            listener.local_addr()?.port()
        };
        let uri = format!("http://127.0.0.1:{port}/snapshot.jpg?token=PRIVATE-TOKEN");
        let snapshot = format!(
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><trt:GetSnapshotUriResponse><trt:MediaUri><tt:Uri>{uri}</tt:Uri></trt:MediaUri></trt:GetSnapshotUriResponse></s:Body></s:Envelope>"
        );
        let body = match index {
            0 => PROFILES.as_bytes(),
            1 => snapshot.as_bytes(),
            _ => &case.body,
        };
        let status = if index == 0 { case.first_status } else { 200 };
        let mime = if index == 2 {
            "image/jpeg"
        } else {
            "application/soap+xml"
        };
        if index == 2 {
            std::thread::sleep(case.delay);
        }
        let mut response = if case.chunked && index == 2 {
            format!("HTTP/1.1 {status} PRIVATE-REASON\r\nContent-Type: {mime}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").into_bytes()
        } else {
            format!("HTTP/1.1 {status} PRIVATE-REASON\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes()
        };
        if case.chunked && index == 2 {
            for chunk in body.chunks(13) {
                response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                response.extend_from_slice(chunk);
                response.extend_from_slice(b"\r\n");
            }
            response.extend_from_slice(b"0\r\n\r\n");
        } else {
            response.extend_from_slice(body);
        }
        // A cancelled/expired owner may close before the final response is written.
        if let Err(error) = stream.write_all(&response) {
            if !(index == 2 && (case.cancel || !case.delay.is_zero())) {
                return Err(error.into());
            }
        }
    }
    Ok(requests)
}

fn capture(case: Case) -> Test<(Result<Snapshot, ClientError>, Vec<String>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let peer = listener.local_addr()?;
    let media = HttpRoute::new(
        peer,
        &peer.to_string(),
        "/onvif/media",
        1,
        ContentDigest::sha256(b"snapshot-test-approval"),
    )?;
    let plan = SnapshotPlan {
        media: media.clone(),
        profile_token: Some("video".into()),
        max_source_bytes: case.max_bytes,
        deadline_ns: case.deadline_ns,
        max_steps: 100_000,
    };
    let owner = Owner {
        start: Instant::now(),
        media,
        cancelled_read: case.cancel,
        authorizations: Cell::new(0),
    };
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| serve(listener, &case));
        let result = snapshot::capture(&plan, &owner);
        let requests = worker.join().map_err(|_| "server panicked")??;
        assert_eq!(owner.authorizations.get(), 0);
        Ok((result, requests))
    })
}

#[test]
fn native_content_length_and_chunked_snapshots_preserve_exact_source() -> Test {
    for chunked in [false, true] {
        let (result, requests) = capture(Case {
            chunked,
            ..Case::default()
        })?;
        let snapshot = result?;
        assert_eq!(snapshot.jpeg, JPEG);
        assert_eq!(snapshot.source_digest, ContentDigest::sha256(JPEG));
        assert_eq!(snapshot.profile.token, "video");
        assert_eq!(requests.len(), 3);
        assert!(requests[0].contains("/GetProfiles"));
        assert!(requests[1].contains("/GetSnapshotUri"));
        assert!(requests[2].starts_with("GET /snapshot.jpg?token=PRIVATE-TOKEN HTTP/1.1"));
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("Authorization:"))
        );
        assert!(!format!("{snapshot:?}").contains("PRIVATE"));
        assert!(snapshot.network.received_bytes > JPEG.len() as u64);
    }
    Ok(())
}

#[test]
fn returned_uri_cannot_broaden_approved_peer_or_origin() -> Test {
    let (result, requests) = capture(Case {
        other_origin: true,
        ..Case::default()
    })?;
    assert!(matches!(result, Err(ClientError::Scope)));
    assert_eq!(requests.len(), 2);
    Ok(())
}

#[test]
fn over_limit_truncated_multiple_and_non_jpeg_bodies_cannot_be_source() -> Test {
    let (result, _) = capture(Case {
        max_bytes: JPEG.len() - 1,
        ..Case::default()
    })?;
    assert!(result.is_err());
    for body in [
        JPEG[..JPEG.len() - 2].to_vec(),
        [JPEG, JPEG].concat(),
        b"not a jpeg".to_vec(),
    ] {
        let (result, _) = capture(Case {
            body,
            ..Case::default()
        })?;
        assert!(matches!(result, Err(ClientError::Unsupported)));
    }
    Ok(())
}

#[test]
fn cancellation_deadline_auth_and_redirect_refusals_release_no_source() -> Test {
    let (result, _) = capture(Case {
        cancel: true,
        ..Case::default()
    })?;
    assert!(matches!(result, Err(ClientError::Cancelled)));
    let (result, _) = capture(Case {
        delay: Duration::from_millis(300),
        deadline_ns: 200_000_000,
        ..Case::default()
    })?;
    assert!(matches!(result, Err(ClientError::Deadline)));
    for first_status in [401, 302] {
        let (result, requests) = capture(Case {
            first_status,
            ..Case::default()
        })?;
        let error = result.err().ok_or("unexpected source")?;
        assert!(matches!(
            error,
            ClientError::AuthenticationRequired | ClientError::HttpStatus(302)
        ));
        assert!(!format!("{error:?}").contains("PRIVATE"));
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}
