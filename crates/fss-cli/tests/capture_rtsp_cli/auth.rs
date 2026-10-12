#![forbid(unsafe_code)]
//! Owned loopback authentication-to-custody fixtures. All credentials are synthetic
//! leak canaries; no device/account credentials are checked in or discovered.

use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

const USERNAME: &str = "FSS_RTSP_SYNTHETIC_USERNAME_CANARY";
const PASSWORD: &str = "FSS_RTSP_SYNTHETIC_PASSWORD_CANARY";
const NEXT_NONCE: &str = "FSS_RTSP_SYNTHETIC_SECOND_NONCE";

fn credential_file(directory: &Directory) -> Test<PathBuf> {
    let path = directory.0.join("credential");
    fs::write(&path, format!("{USERNAME}\n{PASSWORD}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

fn auth_args(
    directory: &Directory,
    peer: SocketAddr,
    file: &std::path::Path,
) -> Test<Vec<OsString>> {
    let mut arguments = args(directory, peer, 2);
    arguments.extend([
        "--credential-file".into(),
        file.as_os_str().to_owned(),
        "--auth-realm".into(),
        SECRET_REALM.into(),
    ]);
    Ok(arguments)
}

struct Request {
    method: String,
    target: String,
    cseq: u32,
    authorization: Option<String>,
}

fn read_request(peer: &mut TcpStream) -> Test<Option<Request>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("client closed inside an RTSP request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset && bytes.is_empty() => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        if !bytes.ends_with(b"\r\n\r\n") {
            continue;
        }
        let wire = String::from_utf8(bytes)?;
        assert!(
            !wire.contains(PASSWORD),
            "plaintext password was dispatched"
        );
        let mut lines = wire.split("\r\n");
        let mut start = lines
            .next()
            .ok_or("missing request start")?
            .split_ascii_whitespace();
        let method = start.next().ok_or("missing method")?.to_owned();
        let target = start.next().ok_or("missing target")?.to_owned();
        assert_eq!(start.next(), Some("RTSP/1.0"));
        assert!(start.next().is_none());
        let mut cseq = None;
        let mut authorization = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("malformed request header")?;
            if name.eq_ignore_ascii_case("cseq") {
                assert!(cseq.replace(value.trim().parse()?).is_none());
            }
            if name.eq_ignore_ascii_case("authorization") {
                assert!(authorization.replace(value.trim().to_owned()).is_none());
            }
        }
        return Ok(Some(Request {
            method,
            target,
            cseq: cseq.ok_or("missing cseq")?,
            authorization,
        }));
    }
    Err("request exceeded fixture bound".into())
}

fn signed_fields(request: &Request, nonce: &str, count: u32, algorithm: &str) -> Test<String> {
    let header = request
        .authorization
        .as_deref()
        .ok_or("signed request has no Authorization")?;
    let body = header
        .strip_prefix("Digest ")
        .ok_or("unexpected authentication scheme")?;
    let mut fields = BTreeMap::new();
    for field in body.split(',') {
        let (name, value) = field
            .trim()
            .split_once('=')
            .ok_or("invalid Digest directive")?;
        assert!(fields.insert(name, value.trim_matches('"')).is_none());
    }
    let get = |key| fields.get(key).copied().ok_or("missing Digest directive");
    assert_eq!(get("username")?, USERNAME);
    assert_eq!(get("realm")?, SECRET_REALM);
    assert_eq!(get("nonce")?, nonce);
    assert_eq!(get("uri")?, request.target);
    assert_eq!(get("algorithm")?, algorithm);
    assert_eq!(get("qop")?, "auth");
    assert_eq!(get("nc")?, format!("{count:08x}"));
    let cnonce = get("cnonce")?;
    assert_eq!(cnonce.len(), 32);
    assert!(cnonce.bytes().all(|b| b.is_ascii_hexdigit()));
    // Independent SHA-256 response composition checks the actual wire method,
    // exact URI, increasing counter, and fresh owner cnonce. It does not call the
    // production challenge or Authorization generator.
    let hash = |text: &str| ContentDigest::sha256(text.as_bytes()).to_text()[7..].to_owned();
    let mut a1 = hash(&format!("{USERNAME}:{SECRET_REALM}:{PASSWORD}"));
    if algorithm == "SHA-256-sess" {
        a1 = hash(&format!("{a1}:{nonce}:{cnonce}"));
    }
    let a2 = hash(&format!("{}:{}", request.method, request.target));
    let expected = hash(&format!("{a1}:{nonce}:{count:08x}:{cnonce}:auth:{a2}"));
    assert_eq!(get("response")?, expected);
    Ok(cnonce.to_owned())
}

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Sha256,
    Sha256Session,
    StaleOnce,
    WrongRealm,
    LegacyRefused,
    BasicRefused,
    RepeatedChallenge,
    ReplayedStaleNonce,
    RetryLimit,
    Downgrade,
    OutsideControlRoot,
    RevokeBeforeRetry,
    RevokeAfterDescribe,
}

fn challenge(
    peer: &mut TcpStream,
    cseq: u32,
    realm: &str,
    nonce: &str,
    algorithm: &str,
    stale: bool,
) -> Test {
    peer.write_all(format!(
        "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm={algorithm}, qop=\"auth\", stale={}\r\nContent-Length: 0\r\n\r\n", if stale { "true" } else { "false" }
    ).as_bytes())?;
    Ok(())
}

fn auth_server(listener: TcpListener, scenario: Scenario, credential: PathBuf) -> Test<usize> {
    let address = listener.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    let first = read_request(&mut peer)?.ok_or("missing initial DESCRIBE")?;
    assert_eq!(first.method, "DESCRIBE");
    assert_eq!(first.target, format!("rtsp://{address}/live/"));
    assert_eq!(first.cseq, 1);
    assert!(first.authorization.is_none());
    let algorithm = if matches!(scenario, Scenario::Sha256Session) {
        "SHA-256-sess"
    } else {
        "SHA-256"
    };
    if matches!(scenario, Scenario::RevokeBeforeRetry) {
        fs::remove_file(&credential)?;
    }
    if matches!(scenario, Scenario::BasicRefused) {
        peer.write_all(format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Basic realm=\"{SECRET_REALM}\"\r\nContent-Length: 0\r\n\r\n", first.cseq).as_bytes())?;
    } else {
        challenge(
            &mut peer,
            first.cseq,
            if matches!(scenario, Scenario::WrongRealm) {
                "different-private-realm"
            } else {
                SECRET_REALM
            },
            SECRET_NONCE,
            if matches!(scenario, Scenario::LegacyRefused) {
                "MD5"
            } else {
                algorithm
            },
            false,
        )?;
    }
    if matches!(
        scenario,
        Scenario::WrongRealm
            | Scenario::LegacyRefused
            | Scenario::BasicRefused
            | Scenario::RevokeBeforeRetry
    ) {
        assert!(
            read_request(&mut peer)?.is_none(),
            "refused scope dispatched another request"
        );
        return Ok(0);
    }
    let mut current = read_request(&mut peer)?.ok_or("missing authenticated DESCRIBE")?;
    assert_eq!(current.cseq, 2);
    assert_eq!(current.method, first.method);
    assert_eq!(current.target, first.target);
    let mut cnonces = vec![signed_fields(&current, SECRET_NONCE, 1, algorithm)?];
    if matches!(
        scenario,
        Scenario::RepeatedChallenge | Scenario::ReplayedStaleNonce | Scenario::Downgrade
    ) {
        challenge(
            &mut peer,
            current.cseq,
            SECRET_REALM,
            if matches!(scenario, Scenario::Downgrade) {
                NEXT_NONCE
            } else {
                SECRET_NONCE
            },
            if matches!(scenario, Scenario::Downgrade) {
                "MD5"
            } else {
                algorithm
            },
            !matches!(scenario, Scenario::RepeatedChallenge),
        )?;
        assert!(
            read_request(&mut peer)?.is_none(),
            "replayed or weaker challenge was answered"
        );
        return Ok(1);
    }
    let nonce = if matches!(scenario, Scenario::StaleOnce | Scenario::RetryLimit) {
        challenge(
            &mut peer,
            current.cseq,
            SECRET_REALM,
            NEXT_NONCE,
            algorithm,
            true,
        )?;
        current = read_request(&mut peer)?.ok_or("missing valid stale-nonce retry")?;
        assert_eq!(current.cseq, 3);
        assert_eq!(current.method, first.method);
        assert_eq!(current.target, first.target);
        cnonces.push(signed_fields(&current, NEXT_NONCE, 1, algorithm)?);
        if matches!(scenario, Scenario::RetryLimit) {
            challenge(
                &mut peer,
                current.cseq,
                SECRET_REALM,
                "third-nonce",
                algorithm,
                true,
            )?;
            assert!(
                read_request(&mut peer)?.is_none(),
                "third authentication response exceeded retry limit"
            );
            return Ok(2);
        }
        NEXT_NONCE
    } else {
        SECRET_NONCE
    };
    if matches!(scenario, Scenario::RevokeAfterDescribe) {
        let replacement = credential.with_extension("rotated");
        fs::write(&replacement, format!("{USERNAME}\n{PASSWORD}\n"))?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
        fs::rename(&replacement, &credential)?;
    }
    let sdp = if matches!(scenario, Scenario::OutsideControlRoot) {
        SDP.replace(
            "a=control:trackID=0",
            "a=control:rtsp://other.example/private/track",
        )
    } else {
        SDP.to_owned()
    };
    response(
        &mut peer,
        current.cseq,
        "Content-Type: application/sdp\r\n",
        &sdp,
    )?;
    if matches!(
        scenario,
        Scenario::OutsideControlRoot | Scenario::RevokeAfterDescribe
    ) {
        assert!(
            read_request(&mut peer)?.is_none(),
            "invalidated scope dispatched a signed SETUP"
        );
        return Ok(cnonces.len());
    }
    let setup = read_request(&mut peer)?.ok_or("missing signed SETUP")?;
    assert_eq!(setup.method, "SETUP");
    assert_eq!(setup.cseq, current.cseq + 1);
    assert_eq!(setup.target, format!("rtsp://{address}/live/trackID=0"));
    cnonces.push(signed_fields(&setup, nonce, 2, algorithm)?);
    response(
        &mut peer,
        setup.cseq,
        "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
        "",
    )?;
    let play = read_request(&mut peer)?.ok_or("missing signed PLAY")?;
    assert_eq!(play.method, "PLAY");
    assert_eq!(play.cseq, setup.cseq + 1);
    assert_eq!(play.target, first.target);
    cnonces.push(signed_fields(&play, nonce, 3, algorithm)?);
    response(&mut peer, play.cseq, "Session: fixture\r\n", "")?;
    peer.write_all(&video(2, 3600, 96, false)?)?;
    assert!(
        read_request(&mut peer)?.is_none(),
        "target stop dispatched an unexpected operation"
    );
    for (index, nonce) in cnonces.iter().enumerate() {
        assert!(!cnonces[..index].contains(nonce), "owner reused a cnonce");
    }
    Ok(cnonces.len())
}

fn auth_capture(
    listener: TcpListener,
    args: &[OsString],
    scenario: Scenario,
    credential: PathBuf,
) -> Test<(Output, usize)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || auth_server(listener, scenario, credential));
        let output = run("capture", args)?;
        let signed = server
            .join()
            .map_err(|_| "authentication server panicked")??;
        Ok((output, signed))
    })
}

fn no_secret_bytes(bytes: &[u8]) {
    for secret in [
        USERNAME,
        PASSWORD,
        SECRET_REALM,
        SECRET_NONCE,
        NEXT_NONCE,
        "Authorization:",
        "WWW-Authenticate:",
    ] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "secret material entered retained or public bytes"
        );
    }
}

fn secret_free_output_and_archive(directory: &Directory, output: &Output) -> Test {
    no_secret_bytes(&output.stdout);
    no_secret_bytes(&output.stderr);
    let mut paths = vec![directory.root(), directory.pins()];
    let mut visited = 0;
    while let Some(path) = paths.pop() {
        if !path.exists() {
            continue;
        }
        visited += 1;
        assert!(visited <= 4096, "fixture archive traversal exceeded budget");
        if path.is_dir() {
            for child in fs::read_dir(path)? {
                paths.push(child?.path());
            }
        } else {
            let bytes = fs::read(path)?;
            no_secret_bytes(&bytes);
        }
    }
    Ok(())
}

#[test]
fn approved_digest_capture_cold_imports_and_decodes_originals_without_secret_leaks() -> Test {
    let directory = Directory::new("digest-native")?;
    let listener = listener()?;
    let credential = credential_file(&directory)?;
    let arguments = approve(&auth_args(&directory, listener.local_addr()?, &credential)?)?;
    let (output, signed) = auth_capture(listener, &arguments, Scenario::Sha256, credential)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(signed, 3);
    secret_free_output_and_archive(&directory, &output)?;
    let report = rows(&output)?;
    let terminal = detail(&report, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "authentication_challenges")?, 1);
    assert_eq!(integer(terminal, "authentication_responses_queued")?, 1);
    assert_eq!(integer(terminal, "digest_requests_queued")?, 3);
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    assert!(!boolean(terminal, "peer_eof")?);
    assert!(!boolean(terminal, "server_identity_verified")?);
    assert!(!boolean(terminal, "transport_encrypted")?);
    import_and_decode(&directory, &report, 2)
}

#[test]
fn sha256_session_and_one_fresh_stale_nonce_complete_with_distinct_cnonces() -> Test {
    for scenario in [Scenario::Sha256Session, Scenario::StaleOnce] {
        let directory = Directory::new("digest-variants")?;
        let listener = listener()?;
        let credential = credential_file(&directory)?;
        let arguments = approve(&auth_args(&directory, listener.local_addr()?, &credential)?)?;
        let (output, signed) = auth_capture(listener, &arguments, scenario, credential)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            signed,
            if matches!(scenario, Scenario::StaleOnce) {
                4
            } else {
                3
            }
        );
        secret_free_output_and_archive(&directory, &output)?;
        let report = rows(&output)?;
        assert_eq!(
            integer(detail(&report, "terminal")?, "durable_pictures")?,
            2
        );
    }
    Ok(())
}

#[test]
fn invalid_authentication_replay_downgrade_and_retry_exhaustion_stop_without_publication() -> Test {
    for scenario in [
        Scenario::WrongRealm,
        Scenario::LegacyRefused,
        Scenario::BasicRefused,
        Scenario::RepeatedChallenge,
        Scenario::ReplayedStaleNonce,
        Scenario::RetryLimit,
        Scenario::Downgrade,
    ] {
        let directory = Directory::new("digest-refused")?;
        let listener = listener()?;
        let credential = credential_file(&directory)?;
        let mut arguments = auth_args(&directory, listener.local_addr()?, &credential)?;
        // An explicit MD5 allowance still cannot downgrade an established SHA-256 challenge.
        if matches!(scenario, Scenario::Downgrade) {
            arguments.extend(["--legacy-md5".into(), "yes".into()]);
        }
        let arguments = approve(&arguments)?;
        let (output, signed) = auth_capture(listener, &arguments, scenario, credential)?;
        assert!(!output.status.success());
        assert!(signed <= 2);
        secret_free_output_and_archive(&directory, &output)?;
        let report = rows(&output)?;
        let terminal = detail(&report, "terminal")?;
        assert_eq!(
            text(terminal, "stop_cause")?,
            "authentication_refused",
            "{scenario:?}"
        );
        assert_eq!(integer(terminal, "durable_windows")?, 0);
        assert_eq!(integer(terminal, "digest_requests_queued")?, signed as i128);
    }
    Ok(())
}

#[test]
fn credential_revocation_and_camera_control_scope_drift_stop_before_next_signed_request() -> Test {
    for scenario in [
        Scenario::RevokeBeforeRetry,
        Scenario::RevokeAfterDescribe,
        Scenario::OutsideControlRoot,
    ] {
        let directory = Directory::new("digest-revocation")?;
        let listener = listener()?;
        let credential = credential_file(&directory)?;
        let arguments = approve(&auth_args(&directory, listener.local_addr()?, &credential)?)?;
        let (output, signed) = auth_capture(listener, &arguments, scenario, credential)?;
        assert!(!output.status.success());
        assert!(signed <= 1);
        secret_free_output_and_archive(&directory, &output)?;
        let report = rows(&output)?;
        let terminal = detail(&report, "terminal")?;
        assert_eq!(
            text(terminal, "stop_cause")?,
            if matches!(scenario, Scenario::OutsideControlRoot) {
                "protocol_failure"
            } else {
                "authority_refused"
            }
        );
        assert_eq!(integer(terminal, "durable_windows")?, 0);
    }
    Ok(())
}

#[test]
fn secret_file_is_unread_during_preview_and_refused_before_network_or_storage() -> Test {
    let directory = Directory::new("digest-secret-input")?;
    let listener = listener()?;
    let file = directory.0.join("not-created-secret");
    let arguments = auth_args(&directory, listener.local_addr()?, &file)?;
    let (preview, approval) = plan(&arguments)?;
    assert_eq!(text(&preview, "authentication")?, "digest");
    assert!(!boolean(
        value(&preview, "authentication_scope")?,
        "credentials_read"
    )?);
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    no_connection(&listener)?;
    let mut approved = arguments;
    approved.extend(["--approve".into(), approval.into()]);
    let output = run("capture", &approved)?;
    assert!(!output.status.success());
    no_secret_bytes(&output.stdout);
    no_secret_bytes(&output.stderr);
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    let report = rows(&output)?;
    assert_eq!(
        text(detail(&report, "terminal")?, "stop_cause")?,
        "credential_refused"
    );
    Ok(())
}
