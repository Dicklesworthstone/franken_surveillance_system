#![forbid(unsafe_code)]
//! Real-process loopback ONVIF onboarding through existing RTSP custody and decode.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;

const PROFILE: &str = "ONVIF_PRIVATE_PROFILE_CANARY";
const QUERY: &str = "ONVIF_PRIVATE_URI_CANARY";
const USER: &str = "ONVIF_SYNTHETIC_USER_CANARY";
const PASSWORD: &str = "ONVIF_SYNTHETIC_PASSWORD_CANARY";
const REALM: &str = "ONVIF_SYNTHETIC_REALM_CANARY";
const NONCE: &str = "ONVIF_SYNTHETIC_NONCE_CANARY";

fn envelope(body: &str) -> String {
    format!(
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:d=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:m=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:t=\"http://www.onvif.org/ver10/schema\"><s:Body>{body}</s:Body></s:Envelope>"
    )
}
fn accept(listener: &TcpListener) -> Test<TcpStream> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((peer, _)) => {
                peer.set_read_timeout(Some(Duration::from_secs(5)))?;
                peer.set_write_timeout(Some(Duration::from_secs(5)))?;
                return Ok(peer);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error.into()),
        }
    }
}
struct HttpRequest {
    target: String,
    authorization: Option<String>,
    body: String,
}
fn http_request(peer: &mut TcpStream) -> Test<HttpRequest> {
    let mut bytes = Vec::new();
    while bytes.len() < 32768 {
        let mut byte = [0];
        if peer.read(&mut byte)? == 0 {
            return Err("incomplete HTTP request".into());
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let headers = String::from_utf8(bytes)?;
    assert!(headers.ends_with("\r\n\r\n"));
    let mut lines = headers.split("\r\n");
    let mut start = lines
        .next()
        .ok_or("missing start")?
        .split_ascii_whitespace();
    assert_eq!(start.next(), Some("POST"));
    let target = start.next().ok_or("missing target")?.to_owned();
    assert_eq!(start.next(), Some("HTTP/1.1"));
    let mut size = None;
    let mut authorization = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("bad header")?;
        if name.eq_ignore_ascii_case("content-length") {
            size = Some(value.trim().parse::<usize>()?);
        }
        if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_owned());
        }
    }
    let size = size.ok_or("missing size")?;
    assert!(size < 32768);
    let mut body = vec![0; size];
    peer.read_exact(&mut body)?;
    let body = String::from_utf8(body)?;
    assert!(!headers.contains(PASSWORD) && !body.contains(PASSWORD));
    Ok(HttpRequest {
        target,
        authorization,
        body,
    })
}
fn signed(request: &HttpRequest, nonce: &str) -> Test<String> {
    let header = request
        .authorization
        .as_deref()
        .ok_or("missing signed retry")?;
    let mut fields = BTreeMap::new();
    for field in header
        .strip_prefix("Digest ")
        .ok_or("not Digest")?
        .split(',')
    {
        let (key, value) = field.trim().split_once('=').ok_or("bad Digest field")?;
        assert!(fields.insert(key, value.trim_matches('"')).is_none());
    }
    let get = |key| fields.get(key).copied().ok_or("missing Digest field");
    assert_eq!(get("username")?, USER);
    assert_eq!(get("realm")?, REALM);
    assert_eq!(get("nonce")?, nonce);
    assert_eq!(get("uri")?, request.target);
    assert_eq!(get("algorithm")?, "SHA-256");
    assert_eq!(get("qop")?, "auth");
    assert_eq!(get("nc")?, "00000001");
    let cnonce = get("cnonce")?;
    assert_eq!(cnonce.len(), 32);
    let hash = |text: &str| ContentDigest::sha256(text.as_bytes()).to_text()[7..].to_owned();
    let a1 = hash(&format!("{USER}:{REALM}:{PASSWORD}"));
    let a2 = hash(&format!("POST:{}", request.target));
    assert_eq!(
        get("response")?,
        hash(&format!("{a1}:{nonce}:00000001:{cnonce}:auth:{a2}"))
    );
    Ok(cnonce.into())
}
fn soap_reply(peer: &mut TcpStream, body: &str) -> Test {
    peer.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
    Ok(())
}

fn soap_server(
    listener: TcpListener,
    rtsp: SocketAddr,
    authenticated: bool,
    selection: bool,
    hostile_media: bool,
) -> Test<usize> {
    let http = listener.local_addr()?;
    let mut nonces = BTreeSet::new();
    let count = if hostile_media {
        1
    } else if selection {
        3
    } else {
        2
    };
    for operation in 0..count {
        let mut peer = accept(&listener)?;
        let mut request = http_request(&mut peer)?;
        assert!(request.authorization.is_none());
        let expected_target = if operation == 0 {
            "/onvif/device_service"
        } else {
            "/onvif/media_service"
        };
        assert_eq!(request.target, expected_target);
        if authenticated {
            let nonce = format!("{NONCE}-{operation}");
            peer.write_all(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{REALM}\",nonce=\"{nonce}\",algorithm=SHA-256,qop=\"auth\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())?;
            drop(peer);
            peer = accept(&listener)?;
            let retry = http_request(&mut peer)?;
            assert_eq!(retry.target, request.target);
            assert_eq!(retry.body, request.body);
            assert!(
                nonces.insert(signed(&retry, &nonce)?),
                "every exchange needs fresh cnonce"
            );
            request = retry;
        }
        let body = match operation {
            0 => {
                assert!(request.body.contains("GetCapabilities"));
                let endpoint = if hostile_media {
                    format!("http://{rtsp}/onvif/media_service")
                } else {
                    format!("http://{http}/onvif/media_service")
                };
                envelope(&format!(
                    "<d:GetCapabilitiesResponse><d:Capabilities><t:Media><t:XAddr>{endpoint}</t:XAddr><t:StreamingCapabilities><t:RTP_RTSP_TCP>true</t:RTP_RTSP_TCP></t:StreamingCapabilities></t:Media></d:Capabilities></d:GetCapabilitiesResponse>"
                ))
            }
            1 => {
                assert!(request.body.contains("GetProfiles"));
                envelope(&format!(
                    "<m:GetProfilesResponse><m:Profiles token=\"{PROFILE}\"><t:Name>Private camera name</t:Name><t:VideoEncoderConfiguration><t:Encoding>H264</t:Encoding><t:Resolution><t:Width>160</t:Width><t:Height>120</t:Height></t:Resolution></t:VideoEncoderConfiguration></m:Profiles><m:Profiles token=\"audio_only\"><t:Name>Audio disabled</t:Name></m:Profiles></m:GetProfilesResponse>"
                ))
            }
            _ => {
                assert!(request.body.contains("GetStreamUri") && request.body.contains(PROFILE));
                envelope(&format!(
                    "<m:GetStreamUriResponse><m:MediaUri><t:Uri>rtsp://{rtsp}/live/?channel=1&amp;selection={QUERY}%2B</t:Uri><t:InvalidAfterConnect>false</t:InvalidAfterConnect><t:InvalidAfterReboot>false</t:InvalidAfterReboot><t:Timeout>P0DT0H0M0S</t:Timeout></m:MediaUri></m:GetStreamUriResponse>"
                ))
            }
        };
        soap_reply(&mut peer, &body)?;
    }
    no_connection(&listener)?;
    Ok(count * if authenticated { 2 } else { 1 })
}

fn onvif_args(
    directory: &Directory,
    http: SocketAddr,
    rtsp: Option<SocketAddr>,
    authenticated: bool,
) -> Test<Vec<OsString>> {
    let mut args: Vec<_> = [
        ("--peer", http.to_string()),
        ("--authority", http.to_string()),
        ("--device-path", "/onvif/device_service".into()),
        ("--service-root", "/onvif".into()),
        (
            "--output",
            directory.0.join("onvif.json").display().to_string(),
        ),
        ("--owner-authorized", "yes".into()),
        ("--plaintext", "yes".into()),
        ("--timeout-ms", "5000".into()),
    ]
    .into_iter()
    .flat_map(|(key, value)| [key.into(), OsString::from(value)])
    .collect();
    if let Some(rtsp) = rtsp {
        args.extend([
            "--profile".into(),
            PROFILE.into(),
            "--rtsp-peer".into(),
            rtsp.to_string().into(),
            "--rtsp-authority".into(),
            rtsp.to_string().into(),
        ]);
    }
    if authenticated {
        let path = directory.0.join("credentials");
        fs::write(&path, format!("{USER}\n{PASSWORD}\n"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        args.extend([
            "--credential-file".into(),
            path.into_os_string(),
            "--auth-realm".into(),
            REALM.into(),
        ]);
    }
    Ok(args)
}

fn approved_onvif(args: &[OsString]) -> Test<Vec<OsString>> {
    let plan = parse(&good(run("onvif", args)?)?)?;
    let mut result = args.to_owned();
    result.extend(["--approve".into(), text(&plan, "approval")?.into()]);
    Ok(result)
}
fn secret_free(output: &Output) {
    for secret in [
        PROFILE,
        QUERY,
        USER,
        PASSWORD,
        REALM,
        NONCE,
        "Private camera name",
    ] {
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(secret),
            "stdout disclosure"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(secret),
            "stderr disclosure"
        );
    }
}

#[test]
fn onvif_preview_and_wrong_approval_open_no_secret_output_or_camera() -> Test {
    let directory = Directory::new("onvif-pure")?;
    let http = listener()?;
    let mut args = onvif_args(&directory, http.local_addr()?, None, false)?;
    args.extend([
        "--credential-file".into(),
        directory.0.join("missing-credential").into_os_string(),
        "--auth-realm".into(),
        REALM.into(),
    ]);
    let output = run("onvif", &args)?;
    secret_free(&output);
    good(output)?;
    no_connection(&http)?;
    assert!(!directory.0.join("onvif.json").exists());
    args.extend(["--approve".into(), digest("wrong approval").into()]);
    let refused = run("onvif", &args)?;
    assert!(!refused.status.success());
    secret_free(&refused);
    no_connection(&http)?;
    assert!(!directory.0.join("onvif.json").exists());
    Ok(())
}

#[test]
fn onvif_profile_inventory_is_private_and_does_not_contact_rtsp() -> Test {
    let directory = Directory::new("onvif-inventory")?;
    let http = listener()?;
    let http_fence = http.try_clone()?;
    let rtsp = listener()?;
    let args = approved_onvif(&onvif_args(&directory, http.local_addr()?, None, false)?)?;
    let address = rtsp.local_addr()?;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || soap_server(http, address, false, false, false));
        let output = run("onvif", &args)?;
        assert_eq!(server.join().map_err(|_| "SOAP fixture panicked")??, 2);
        Ok(output)
    })?;
    secret_free(&output);
    let result = parse(&good(output)?)?;
    assert!(!boolean(&result, "handoff_ready")?);
    assert_eq!(integer(&result, "profiles")?, 2);
    let path = directory.0.join("onvif.json");
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    let bytes = fs::read(&path)?;
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        text(&result, "output_digest")?
    );
    let inventory = parse(std::str::from_utf8(&bytes)?)?;
    assert_eq!(text(&inventory, "schema")?, "fss.onvif_media1_inventory.v1");
    no_connection(&rtsp)?;
    let second = run("onvif", &args)?;
    assert!(!second.status.success());
    secret_free(&second);
    no_connection(&http_fence)?;
    assert_eq!(
        fs::read(&path)?,
        bytes,
        "existing private output is never overwritten"
    );
    Ok(())
}

#[test]
fn onvif_foreign_media_origin_is_never_followed_or_given_credentials() -> Test {
    let directory = Directory::new("onvif-foreign")?;
    let http = listener()?;
    let foreign = listener()?;
    let args = approved_onvif(&onvif_args(&directory, http.local_addr()?, None, true)?)?;
    let address = foreign.local_addr()?;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || soap_server(http, address, true, false, true));
        let output = run("onvif", &args)?;
        assert_eq!(server.join().map_err(|_| "SOAP fixture panicked")??, 2);
        Ok(output)
    })?;
    secret_free(&output);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERR-ONVIF-SCOPE-001"));
    assert!(!directory.0.join("onvif.json").exists());
    no_connection(&foreign)?;
    Ok(())
}

#[test]
fn onvif_credential_revocation_before_challenge_prevents_retry_and_output() -> Test {
    let directory = Directory::new("onvif-revoked")?;
    let http = listener()?;
    let fence = http.try_clone()?;
    let args = approved_onvif(&onvif_args(&directory, http.local_addr()?, None, true)?)?;
    let credential = directory.0.join("credentials");
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || -> Test {
            let mut peer = accept(&http)?;
            let request = http_request(&mut peer)?;
            assert!(request.authorization.is_none());
            fs::remove_file(credential)?;
            peer.write_all(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{REALM}\",nonce=\"{NONCE}\",algorithm=SHA-256,qop=\"auth\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())?;
            Ok(())
        });
        let output = run("onvif", &args)?;
        server
            .join()
            .map_err(|_| "SOAP revocation fixture panicked")??;
        Ok(output)
    })?;
    assert!(!output.status.success());
    secret_free(&output);
    no_connection(&fence)?;
    assert!(!directory.0.join("onvif.json").exists());
    Ok(())
}

fn capture_arguments(directory: &Directory, peer: SocketAddr, handoff: &str) -> Vec<OsString> {
    let mut selected = vec![OsString::from("from-onvif")];
    for pair in args(directory, peer, 2).as_chunks::<2>().0 {
        if !matches!(
            pair[0].to_str(),
            Some("--peer" | "--authority" | "--presentation")
        ) {
            selected.extend_from_slice(pair);
        }
    }
    selected.extend([
        "--onvif-source".into(),
        directory.0.join("onvif.json").into_os_string(),
        "--onvif-digest".into(),
        handoff.into(),
    ]);
    selected
}

fn synthetic_handoff(address: SocketAddr) -> String {
    use fss_cli::agent_json::{object, string};
    object(&[
        ("schema", string("fss.onvif_rtsp_handoff.v1")),
        (
            "onboarding_plan",
            string(&digest("synthetic onvif approval")),
        ),
        ("profile_digest", string(&digest(PROFILE))),
        ("peer", string(&address.to_string())),
        ("authority", string(&address.to_string())),
        (
            "uri",
            string(&format!("rtsp://{address}/live/?selection={QUERY}")),
        ),
        ("codec", string("avc")),
        ("invalid_after_connect", "false".into()),
        ("invalid_after_reboot", "false".into()),
        ("timeout", string("PT0S")),
        ("capture_authorized", "false".into()),
        ("source_evidence", "false".into()),
    ]) + "\n"
}

#[test]
fn onvif_handoff_replacement_after_preview_requires_new_capture_approval() -> Test {
    let directory = Directory::new("onvif-replaced-handoff")?;
    let rtsp = listener()?;
    let address = rtsp.local_addr()?;
    let bytes = synthetic_handoff(address);
    let path = directory.0.join("onvif.json");
    fs::write(&path, &bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let mut args = capture_arguments(
        &directory,
        address,
        &ContentDigest::sha256(bytes.as_bytes()).to_text(),
    );
    let preview = parse(&good(run("capture", &args)?)?)?;
    args.extend(["--approve".into(), text(&preview, "approval")?.into()]);
    let replacement = directory.0.join("replacement.json");
    fs::write(&replacement, &bytes)?;
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
    fs::rename(replacement, &path)?;
    let output = run("capture", &args)?;
    secret_free(&output);
    assert!(!output.status.success());
    no_connection(&rtsp)?;
    assert!(!directory.root().exists() && !directory.pins().exists());
    Ok(())
}

#[test]
fn onvif_handoff_changed_digest_expiry_and_permissions_refuse_before_capture() -> Test {
    let directory = Directory::new("onvif-invalid-handoff")?;
    let rtsp = listener()?;
    let address = rtsp.local_addr()?;
    let bytes = synthetic_handoff(address);
    let path = directory.0.join("onvif.json");
    fs::write(&path, &bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let expected = ContentDigest::sha256(bytes.as_bytes()).to_text();
    let args = capture_arguments(&directory, address, &expected);
    let changed = bytes.replace("selection=", "changed=");
    fs::write(&path, &changed)?;
    let output = run("capture", &args)?;
    secret_free(&output);
    assert!(!output.status.success());
    let ephemeral = bytes.replace("\"timeout\":\"PT0S\"", "\"timeout\":\"PT1S\"");
    fs::write(&path, &ephemeral)?;
    let output = run(
        "capture",
        &capture_arguments(
            &directory,
            address,
            &ContentDigest::sha256(ephemeral.as_bytes()).to_text(),
        ),
    )?;
    secret_free(&output);
    assert!(!output.status.success());
    fs::write(&path, &bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    let output = run("capture", &args)?;
    secret_free(&output);
    assert!(!output.status.success());
    no_connection(&rtsp)?;
    assert!(!directory.root().exists() && !directory.pins().exists());
    Ok(())
}

fn exact_rtsp_request(peer: &mut TcpStream) -> Test<Option<(String, String, u32)>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        if peer.read(&mut byte)? == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            return Err("missing RTSP request".into());
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let wire = String::from_utf8(bytes)?;
    assert!(wire.ends_with("\r\n\r\n") && !wire.contains("Authorization:"));
    let mut lines = wire.split("\r\n");
    let mut start = lines
        .next()
        .ok_or("missing RTSP start")?
        .split_ascii_whitespace();
    let method = start.next().ok_or("missing method")?.to_owned();
    let target = start.next().ok_or("missing target")?.to_owned();
    assert_eq!(start.next(), Some("RTSP/1.0"));
    let cseq = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("cseq").then_some(value.trim())
        })
        .ok_or("missing cseq")?
        .parse()?;
    Ok(Some((method, target, cseq)))
}

fn exact_query_camera(listener: TcpListener) -> Test<Transcript> {
    let address = listener.local_addr()?;
    let uri = format!("rtsp://{address}/live/?channel=1&selection={QUERY}%2B");
    let mut peer = accept(&listener)?;
    let mut methods = Vec::new();
    for method in ["DESCRIBE", "SETUP", "PLAY"] {
        let (actual, target, cseq) =
            exact_rtsp_request(&mut peer)?.ok_or("missing expected RTSP request")?;
        assert_eq!(actual, method);
        assert_eq!(
            target,
            if method == "SETUP" {
                format!("rtsp://{address}/live/trackID=0")
            } else {
                uri.clone()
            }
        );
        methods.push(actual);
        match method {
            "DESCRIBE" => response(&mut peer, cseq, "Content-Type: application/sdp\r\n", SDP)?,
            "SETUP" => response(
                &mut peer,
                cseq,
                "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                "",
            )?,
            _ => response(&mut peer, cseq, "Session: fixture\r\n", "")?,
        }
    }
    peer.write_all(&video(2, 3600, 96, false)?)?;
    // Keep the source open until the owner closes it. Native target-stop does
    // not require a synthetic TEARDOWN or fabricate source EOF.
    for _ in 0..16 {
        let Some((method, target, cseq)) = exact_rtsp_request(&mut peer)? else {
            return Ok(Transcript {
                methods,
                pictures: 2,
                source_eof: false,
            });
        };
        assert!(matches!(
            method.as_str(),
            "TEARDOWN" | "GET_PARAMETER" | "OPTIONS"
        ));
        assert_eq!(target, uri);
        methods.push(method);
        response(&mut peer, cseq, "Session: fixture\r\n", "")?;
    }
    Err("RTSP query fixture exceeded the request bound".into())
}

#[test]
fn onvif_digest_selected_query_uri_captures_and_cold_decodes_with_owner_pins() -> Test {
    let directory = Directory::new("onvif-native-capture")?;
    let http = listener()?;
    let rtsp = listener()?;
    let address = rtsp.local_addr()?;
    let onvif = approved_onvif(&onvif_args(
        &directory,
        http.local_addr()?,
        Some(address),
        true,
    )?)?;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || soap_server(http, address, true, true, false));
        let output = run("onvif", &onvif)?;
        assert_eq!(server.join().map_err(|_| "SOAP fixture panicked")??, 6);
        Ok(output)
    })?;
    secret_free(&output);
    let selected = parse(&good(output)?)?;
    assert!(boolean(&selected, "handoff_ready")?);
    no_connection(&rtsp)?;
    let mut capture = capture_arguments(&directory, address, text(&selected, "output_digest")?);
    let preview = run("capture", &capture)?;
    secret_free(&preview);
    let preview = parse(&good(preview)?)?;
    assert_eq!(text(&preview, "schema")?, "fss.rtsp_from_onvif_plan.v1");
    let native = value(&preview, "native_capture")?;
    assert_eq!(text(native, "presentation_uri")?, "[redacted]");
    no_connection(&rtsp)?;
    assert!(!directory.root().exists() && !directory.pins().exists());
    capture.extend(["--approve".into(), text(&preview, "approval")?.into()]);
    let (output, transcript) = thread::scope(|scope| -> Test<_> {
        let server = scope.spawn(move || exact_query_camera(rtsp));
        let output = run("capture", &capture)?;
        let transcript = server
            .join()
            .map_err(|_| "RTSP query fixture panicked")?
            .map_err(|error| {
                format!(
                    "RTSP fixture: {error}; capture status={} stdout={} stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })?;
        Ok((output, transcript))
    })?;
    secret_free(&output);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(&transcript.methods[..3], ["DESCRIBE", "SETUP", "PLAY"]);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    import_and_decode(&directory, &rows, 2)
}
