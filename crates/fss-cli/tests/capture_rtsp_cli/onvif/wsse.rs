#![forbid(unsafe_code)]
//! Real processes against a UsernameToken-only camera with an intentionally skewed clock.

use super::*;
use fss_reference::rtsp::sdp::decode_base64;
use fss_tutk::digest::Sha1;

const CAMERA_UTC: &str = "<t:UTCDateTime><t:Time><t:Hour>12</t:Hour><t:Minute>34</t:Minute><t:Second>50</t:Second></t:Time><t:Date><t:Year>2004</t:Year><t:Month>2</t:Month><t:Day>29</t:Day></t:Date></t:UTCDateTime>";

fn clock_body(utc: &str) -> String {
    envelope(&format!(
        "<d:GetSystemDateAndTimeResponse><d:SystemDateAndTime><t:DateTimeType>Manual</t:DateTimeType><t:DaylightSavings>false</t:DaylightSavings>{utc}</d:SystemDateAndTime></d:GetSystemDateAndTimeResponse>"
    ))
}

fn bootstrap(listener: &TcpListener, utc: &str) -> Test {
    let mut peer = accept(listener)?;
    let request = http_request(&mut peer)?;
    assert_eq!(request.target, "/onvif/device_service");
    assert!(request.authorization.is_none());
    assert!(request.body.contains("GetSystemDateAndTime"));
    assert!(!request.body.contains("UsernameToken"));
    assert!(!request.body.contains(USER));
    soap_reply(&mut peer, &clock_body(utc))
}

fn element<'a>(body: &'a str, name: &str) -> Test<&'a str> {
    let opening = format!("<{name}");
    let mut tags = body.match_indices(&opening).filter_map(|(start, _)| {
        let tail = &body[start + opening.len()..];
        let boundary = tail.as_bytes().first().copied()?;
        (boundary == b'>' || boundary.is_ascii_whitespace()).then_some(tail)
    });
    let tail = tags.next().ok_or("missing token field")?;
    assert!(tags.next().is_none(), "duplicate token field");
    let text = tail.split_once('>').ok_or("missing field value")?.1;
    let (value, _) = text
        .split_once(&format!("</{name}>"))
        .ok_or("missing closing tag")?;
    assert!(!value.contains('<'));
    Ok(value)
}

#[derive(Default)]
struct Tokens {
    nonces: BTreeSet<String>,
    digests: BTreeSet<String>,
}

impl Tokens {
    fn verify(&mut self, request: &HttpRequest) -> Test {
        assert!(request.authorization.is_none(), "HTTP and SOAP auth mixed");
        assert!(request.body.contains("<s:Header>"));
        assert!(request.body.contains("<wsse:Security"));
        assert!(
            request.body.contains("s:mustUnderstand=\"true\"")
                || request.body.contains("s:mustUnderstand=\"1\"")
        );
        for namespace in [
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest",
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
        ] {
            assert!(request.body.contains(namespace));
        }
        assert!(!request.body.contains("#PasswordText"));
        assert_eq!(element(&request.body, "wsse:Username")?, USER);
        let created = element(&request.body, "wsu:Created")?;
        // Device UTC differs from host UTC by decades; do not substitute a wall clock.
        let second = created
            .strip_prefix("2004-02-29T12:34:")
            .and_then(|time| time.strip_suffix('Z'))
            .ok_or("Created does not use the camera clock")?
            .parse::<u8>()?;
        assert!((50..=55).contains(&second));
        let nonce_text = element(&request.body, "wsse:Nonce")?;
        let nonce = decode_base64(nonce_text)?;
        assert_eq!(nonce.len(), 16);
        assert!(self.nonces.insert(nonce_text.into()), "nonce reused");
        let proof = element(&request.body, "wsse:Password")?;
        // Independently assemble raw nonce + exact transmitted Created + password.
        let mut expected = Sha1::new();
        expected.update(&nonce);
        expected.update(created.as_bytes());
        expected.update(PASSWORD.as_bytes());
        assert_eq!(decode_base64(proof)?, expected.finish());
        assert!(self.digests.insert(proof.into()));
        Ok(())
    }

    fn assert_private(&self, output: &Output, retained: Option<&[u8]>) {
        secret_free(output);
        for secret in self.nonces.iter().chain(self.digests.iter()) {
            for bytes in [&output.stdout[..], &output.stderr[..]] {
                assert!(!String::from_utf8_lossy(bytes).contains(secret));
            }
            if let Some(bytes) = retained {
                assert!(!String::from_utf8_lossy(bytes).contains(secret));
            }
        }
        if let Some(bytes) = retained {
            for secret in [USER, PASSWORD, "UsernameToken", "2004-02-29"] {
                assert!(!String::from_utf8_lossy(bytes).contains(secret));
            }
        }
    }
}

fn arguments(
    directory: &Directory,
    http: SocketAddr,
    rtsp: Option<SocketAddr>,
) -> Test<Vec<OsString>> {
    let digest = onvif_args(directory, http, rtsp, true)?;
    let mut args = Vec::new();
    for pair in digest.as_chunks::<2>().0 {
        if pair[0] != "--auth-realm" {
            args.extend_from_slice(pair);
        }
    }
    args.extend(["--auth-mode".into(), "username-token".into()]);
    Ok(args)
}

fn serve(
    listener: TcpListener,
    rtsp: SocketAddr,
    selection: bool,
    foreign: bool,
    media2: bool,
) -> Test<Tokens> {
    let http = listener.local_addr()?;
    bootstrap(&listener, CAMERA_UTC)?;
    let mut tokens = Tokens::default();
    let count = if foreign {
        1
    } else if selection {
        3
    } else {
        2
    };
    for operation in 0..count {
        let mut peer = accept(&listener)?;
        let request = http_request(&mut peer)?;
        assert_eq!(
            request.target,
            if operation == 0 {
                "/onvif/device_service"
            } else {
                "/onvif/media_service"
            }
        );
        tokens.verify(&request)?;
        soap_reply(
            &mut peer,
            &operation_body(operation, &request, http, rtsp, foreign, media2),
        )?;
    }
    no_connection(&listener)?;
    Ok(tokens)
}

#[test]
fn username_token_preview_binds_mode_and_does_not_open_missing_credentials() -> Test {
    let directory = Directory::new("wsse-pure")?;
    let http = listener()?;
    let base = onvif_args(&directory, http.local_addr()?, None, false)?;
    let missing = directory.0.join("missing-credential");
    let mut digest = base.clone();
    digest.extend([
        "--credential-file".into(),
        missing.clone().into_os_string(),
        "--auth-realm".into(),
        REALM.into(),
    ]);
    let old = parse(&good(run("onvif", &digest)?)?)?;
    let mut explicit = digest;
    explicit.extend(["--auth-mode".into(), "http-digest".into()]);
    let explicit = parse(&good(run("onvif", &explicit)?)?)?;
    assert_eq!(text(&old, "approval")?, text(&explicit, "approval")?);
    let mut args = base;
    args.extend([
        "--auth-mode".into(),
        "username-token".into(),
        "--credential-file".into(),
        missing.into_os_string(),
    ]);
    let output = run("onvif", &args)?;
    secret_free(&output);
    let plan = parse(&good(output)?)?;
    assert_eq!(text(&plan, "schema")?, "fss.onvif_operator_plan.v3");
    assert_eq!(integer(&plan, "max_http_exchanges")?, 3);
    assert_ne!(text(&old, "approval")?, text(&plan, "approval")?);
    let mut denied = args.clone();
    denied.extend(["--approve".into(), text(&old, "approval")?.into()]);
    let output = run("onvif", &denied)?;
    secret_free(&output);
    assert!(!output.status.success());
    args.extend(["--media-version".into(), "media2".into()]);
    let media2 = parse(&good(run("onvif", &args)?)?)?;
    assert_ne!(text(&plan, "approval")?, text(&media2, "approval")?);
    no_connection(&http)?;
    assert!(!directory.0.join("onvif.json").exists());
    Ok(())
}

#[test]
fn username_token_rejects_mixed_digest_flags_before_any_effect() -> Test {
    let directory = Directory::new("wsse-mixed")?;
    let http = listener()?;
    let args = arguments(&directory, http.local_addr()?, None)?;
    for (key, value) in [
        ("--auth-realm", REALM),
        ("--legacy-md5", "no"),
        ("--legacy-no-qop", "no"),
    ] {
        let mut mixed = args.clone();
        mixed.extend([key.into(), value.into()]);
        let output = run("onvif", &mixed)?;
        secret_free(&output);
        assert!(!output.status.success());
    }
    no_connection(&http)?;
    assert!(!directory.0.join("onvif.json").exists());
    Ok(())
}

#[test]
fn username_token_camera_clock_authenticates_private_media1_inventory() -> Test {
    let directory = Directory::new("wsse-inventory")?;
    let http = listener()?;
    let rtsp = listener()?;
    let address = rtsp.local_addr()?;
    let args = approved_onvif(&arguments(&directory, http.local_addr()?, None)?)?;
    let (output, tokens) = thread::scope(|scope| -> Test<_> {
        let server = scope.spawn(move || serve(http, address, false, false, false));
        let output = run("onvif", &args)?;
        let tokens = server.join().map_err(|_| "WSSE fixture panicked")??;
        Ok((output, tokens))
    })?;
    assert_eq!(tokens.nonces.len(), 2);
    let path = directory.0.join("onvif.json");
    let bytes = fs::read(&path)?;
    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    tokens.assert_private(&output, Some(&bytes));
    let result = parse(&good(output)?)?;
    assert_eq!(integer(&result, "http_exchanges")?, 3);
    assert!(!boolean(&result, "handoff_ready")?);
    assert_eq!(
        text(&parse(std::str::from_utf8(&bytes)?)?, "schema")?,
        "fss.onvif_media1_inventory.v1"
    );
    no_connection(&rtsp)?;
    Ok(())
}

#[test]
fn username_token_media2_handoff_captures_and_cold_decodes_native_hevc() -> Test {
    let directory = Directory::new("wsse-media2-hevc")?;
    let http = listener()?;
    let rtsp = listener()?;
    let address = rtsp.local_addr()?;
    let mut args = arguments(&directory, http.local_addr()?, Some(address))?;
    args.extend(["--media-version".into(), "media2".into()]);
    let preview = parse(&good(run("onvif", &args)?)?)?;
    assert_eq!(integer(&preview, "max_http_exchanges")?, 4);
    let args = approved_onvif(&args)?;
    let (output, tokens) = thread::scope(|scope| -> Test<_> {
        let server = scope.spawn(move || serve(http, address, true, false, true));
        let output = run("onvif", &args)?;
        let tokens = server
            .join()
            .map_err(|_| "WSSE Media2 fixture panicked")??;
        Ok((output, tokens))
    })?;
    assert_eq!(tokens.nonces.len(), 3);
    let bytes = fs::read(directory.0.join("onvif.json"))?;
    tokens.assert_private(&output, Some(&bytes));
    let result = parse(&good(output)?)?;
    assert_eq!(integer(&result, "http_exchanges")?, 4);
    assert!(boolean(&result, "handoff_ready")?);
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        text(&result, "output_digest")?
    );
    no_connection(&rtsp)?;
    let mut capture = hevc_capture_arguments(&directory, address, text(&result, "output_digest")?)?;
    let preview = run("capture", &capture)?;
    tokens.assert_private(&preview, None);
    let plan = parse(&good(preview)?)?;
    assert_eq!(text(value(&plan, "native_capture")?, "codec")?, "hevc");
    capture.extend(["--approve".into(), text(&plan, "approval")?.into()]);
    let output = super::super::hevc::capture_onvif_and_cold_decode(&directory, rtsp, &capture)?;
    tokens.assert_private(&output, None);
    Ok(())
}

#[test]
fn username_token_foreign_service_never_receives_a_request_or_credentials() -> Test {
    let directory = Directory::new("wsse-foreign")?;
    let http = listener()?;
    let foreign = listener()?;
    let address = foreign.local_addr()?;
    let args = approved_onvif(&arguments(&directory, http.local_addr()?, None)?)?;
    let (output, tokens) = thread::scope(|scope| -> Test<_> {
        let server = scope.spawn(move || serve(http, address, false, true, false));
        let output = run("onvif", &args)?;
        let tokens = server.join().map_err(|_| "WSSE scope fixture panicked")??;
        Ok((output, tokens))
    })?;
    tokens.assert_private(&output, None);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERR-ONVIF-SCOPE-001"));
    assert!(!directory.0.join("onvif.json").exists());
    no_connection(&foreign)?;
    Ok(())
}

#[test]
fn username_token_invalid_or_ambiguous_camera_utc_prevents_any_signed_request() -> Test {
    for (label, utc) in [
        ("missing", String::new()),
        ("duplicate", format!("{CAMERA_UTC}{CAMERA_UTC}")),
        ("date", CAMERA_UTC.replace("<t:Year>2004", "<t:Year>2003")),
        (
            "namespace",
            CAMERA_UTC.replace("t:UTCDateTime", "d:UTCDateTime"),
        ),
    ] {
        let directory = Directory::new(&format!("wsse-invalid-{label}"))?;
        let http = listener()?;
        let fence = http.try_clone()?;
        let args = approved_onvif(&arguments(&directory, http.local_addr()?, None)?)?;
        let output = thread::scope(|scope| -> Test<_> {
            let server = scope.spawn(move || bootstrap(&http, &utc));
            let output = run("onvif", &args)?;
            server.join().map_err(|_| "WSSE time fixture panicked")??;
            Ok(output)
        })?;
        secret_free(&output);
        assert!(!output.status.success());
        no_connection(&fence)?;
        assert!(!directory.0.join("onvif.json").exists());
    }
    Ok(())
}

#[test]
fn username_token_credential_revocation_before_signed_response_stops_the_session() -> Test {
    let directory = Directory::new("wsse-revoked")?;
    let http = listener()?;
    let address = http.local_addr()?;
    let fence = http.try_clone()?;
    let args = approved_onvif(&arguments(&directory, address, None)?)?;
    let credential = directory.0.join("credentials");
    let (output, tokens) = thread::scope(|scope| -> Test<_> {
        let server = scope.spawn(move || -> Test<Tokens> {
            bootstrap(&http, CAMERA_UTC)?;
            let mut peer = accept(&http)?;
            let request = http_request(&mut peer)?;
            let mut tokens = Tokens::default();
            tokens.verify(&request)?;
            fs::remove_file(credential)?;
            let body = operation_body(0, &request, address, address, false, false);
            // A revoked owner may close the connection before the fixture writes.
            let _ = soap_reply(&mut peer, &body);
            Ok(tokens)
        });
        let output = run("onvif", &args)?;
        let tokens = server
            .join()
            .map_err(|_| "WSSE revocation fixture panicked")??;
        Ok((output, tokens))
    })?;
    tokens.assert_private(&output, None);
    assert!(!output.status.success());
    no_connection(&fence)?;
    assert!(!directory.0.join("onvif.json").exists());
    Ok(())
}

#[test]
fn username_token_http_challenge_and_soap_fault_never_retry_or_fall_back() -> Test {
    for fault in [false, true] {
        let directory = Directory::new(if fault {
            "wsse-fault"
        } else {
            "wsse-challenge"
        })?;
        let http = listener()?;
        let fence = http.try_clone()?;
        let args = approved_onvif(&arguments(&directory, http.local_addr()?, None)?)?;
        let (output, tokens) = thread::scope(|scope| -> Test<_> {
            let server = scope.spawn(move || -> Test<Tokens> {
                bootstrap(&http, CAMERA_UTC)?;
                let mut peer = accept(&http)?;
                let request = http_request(&mut peer)?;
                let mut tokens = Tokens::default(); tokens.verify(&request)?;
                if fault {
                    let body = envelope(&format!("<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value xmlns:ter=\"http://www.onvif.org/ver10/error\">ter:NotAuthorized</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang=\"en\">{PASSWORD}</s:Text></s:Reason></s:Fault>"));
                    peer.write_all(format!("HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
                } else {
                    peer.write_all(format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{REALM}\",nonce=\"{NONCE}\",algorithm=SHA-256,qop=\"auth\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())?;
                }
                Ok(tokens)
            });
            let output = run("onvif", &args)?;
            let tokens = server
                .join()
                .map_err(|_| "WSSE refusal fixture panicked")??;
            Ok((output, tokens))
        })?;
        tokens.assert_private(&output, None);
        assert!(!output.status.success());
        no_connection(&fence)?;
        assert!(!directory.0.join("onvif.json").exists());
    }
    Ok(())
}
