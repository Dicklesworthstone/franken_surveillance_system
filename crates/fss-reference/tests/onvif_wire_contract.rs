#![forbid(unsafe_code)]
//! Exact-source tests of the no-I/O ONVIF wire boundary, runnable without the
//! larger reference runtime to keep parser qualification independently bounded.

#[path = "../src/onvif/wire.rs"]
mod wire;

#[path = "onvif_wire_contract/time.rs"]
mod time;

use wire::{
    OnvifOperation, SoapFault, SoapFaultCode, SoapFaultSubcode, VideoEncoding, WireError,
    get_capabilities_request, get_profiles_request, get_stream_uri_request, parse_capabilities,
    parse_profiles, parse_soap_fault, parse_stream_uri,
};

const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const DEVICE: &str = "http://www.onvif.org/ver10/device/wsdl";
const MEDIA: &str = "http://www.onvif.org/ver10/media/wsdl";
const MEDIA2: &str = "http://www.onvif.org/ver20/media/wsdl";
const SCHEMA: &str = "http://www.onvif.org/ver10/schema";

fn envelope(content: &str) -> String {
    format!(
        "<s:Envelope xmlns:s='{SOAP}' xmlns:d='{DEVICE}' xmlns:m='{MEDIA}' xmlns:t='{SCHEMA}'><s:Body>{content}</s:Body></s:Envelope>"
    )
}

fn profile(token: &str, encoding: &str) -> String {
    format!(
        "<m:Profiles token='{token}' fixed='1'><t:Name>Main camera</t:Name><t:VideoEncoderConfiguration token='encoder'><t:Encoding>{encoding}</t:Encoding><t:Resolution><t:Width>1920</t:Width><t:Height>1080</t:Height></t:Resolution></t:VideoEncoderConfiguration></m:Profiles>"
    )
}

fn profiles(content: &str) -> String {
    envelope(&format!(
        "<m:GetProfilesResponse>{content}</m:GetProfilesResponse>"
    ))
}

fn uri_response(uri: &str, connect: &str, reboot: &str, timeout: &str) -> String {
    envelope(&format!(
        "<m:GetStreamUriResponse><m:MediaUri><t:Uri>{uri}</t:Uri><t:InvalidAfterConnect>{connect}</t:InvalidAfterConnect><t:InvalidAfterReboot>{reboot}</t:InvalidAfterReboot><t:Timeout>{timeout}</t:Timeout></m:MediaUri></m:GetStreamUriResponse>"
    ))
}

#[test]
fn read_only_request_actions_and_stream_setup_are_exact() -> Result<(), Box<dyn std::error::Error>>
{
    let capabilities = get_capabilities_request();
    assert_eq!(
        capabilities.action(),
        OnvifOperation::GetCapabilities.action()
    );
    assert!(
        std::str::from_utf8(capabilities.body())?.contains("<tds:Category>Media</tds:Category>")
    );
    let profiles = get_profiles_request();
    assert_eq!(profiles.action(), OnvifOperation::GetProfiles.action());
    assert!(std::str::from_utf8(profiles.body())?.contains("<trt:GetProfiles/>"));
    let request = get_stream_uri_request("profile<&\"'>camera")?;
    assert_eq!(request.action(), OnvifOperation::GetStreamUri.action());
    let body = std::str::from_utf8(request.body())?;
    assert!(body.contains("<tt:Stream>RTP_unicast</tt:Stream>"));
    assert!(body.contains("<tt:Protocol>RTSP</tt:Protocol>"));
    assert!(
        body.contains(
            "<trt:ProfileToken>profile&lt;&amp;&quot;&apos;&gt;camera</trt:ProfileToken>"
        )
    );
    assert!(!format!("{request:?}").contains("camera"));
    for token in ["", "line\nbreak", "bad\u{0}"] {
        assert_eq!(get_stream_uri_request(token), Err(WireError::InvalidField));
    }
    assert!(get_stream_uri_request(&"é".repeat(64)).is_ok());
    assert_eq!(
        get_stream_uri_request(&"é".repeat(65)),
        Err(WireError::InvalidField)
    );
    Ok(())
}

#[test]
fn capability_namespaces_are_resolved_including_default_and_shadowed_prefixes()
-> Result<(), WireError> {
    let body = format!(
        "<GetCapabilitiesResponse xmlns='{DEVICE}'><Capabilities><Media xmlns='{SCHEMA}'><XAddr>http://192.0.2.7/onvif/media?x=1&amp;y=2</XAddr><StreamingCapabilities><RTP_RTSP_TCP>true</RTP_RTSP_TCP></StreamingCapabilities></Media></Capabilities></GetCapabilitiesResponse>"
    );
    let parsed = parse_capabilities(envelope(&body).as_bytes())?;
    assert_eq!(
        parsed.media_xaddr.as_deref(),
        Some("http://192.0.2.7/onvif/media?x=1&y=2")
    );
    assert_eq!(parsed.rtp_rtsp_tcp, Some(true));
    assert!(!format!("{parsed:?}").contains("192.0.2.7"));
    let shadowed = format!(
        "<d:GetCapabilitiesResponse><d:Capabilities><d:Media xmlns:d='{SCHEMA}'><d:XAddr>http://192.0.2.7/media</d:XAddr></d:Media></d:Capabilities></d:GetCapabilitiesResponse>"
    );
    let parsed = parse_capabilities(envelope(&shadowed).as_bytes())?;
    assert_eq!(
        parsed.media_xaddr.as_deref(),
        Some("http://192.0.2.7/media")
    );
    assert_eq!(parsed.rtp_rtsp_tcp, None);
    Ok(())
}

#[test]
fn capability_absence_and_false_are_distinct() -> Result<(), WireError> {
    let absent =
        envelope("<d:GetCapabilitiesResponse><d:Capabilities/></d:GetCapabilitiesResponse>");
    let parsed = parse_capabilities(absent.as_bytes())?;
    assert_eq!(parsed.media_xaddr, None);
    assert_eq!(parsed.rtp_rtsp_tcp, None);
    let unsupported = envelope(
        "<d:GetCapabilitiesResponse><d:Capabilities><t:Media><t:XAddr>http://192.0.2.1/media</t:XAddr><t:StreamingCapabilities><t:RTP_RTSP_TCP>0</t:RTP_RTSP_TCP></t:StreamingCapabilities></t:Media></d:Capabilities></d:GetCapabilitiesResponse>",
    );
    assert_eq!(
        parse_capabilities(unsupported.as_bytes())?.rtp_rtsp_tcp,
        Some(false)
    );
    Ok(())
}

#[test]
fn namespace_spoofed_or_wrapped_fields_do_not_supply_values() {
    for body in [
        "<d:GetCapabilitiesResponse><d:Capabilities><t:Media><x:XAddr xmlns:x='urn:attacker'>http://192.0.2.7/media</x:XAddr></t:Media></d:Capabilities></d:GetCapabilitiesResponse>",
        "<d:GetCapabilitiesResponse><d:Capabilities><t:Media><t:Extension><t:XAddr>http://192.0.2.7/media</t:XAddr></t:Extension></t:Media></d:Capabilities></d:GetCapabilitiesResponse>",
    ] {
        assert_eq!(
            parse_capabilities(envelope(body).as_bytes()),
            Err(WireError::MissingField)
        );
    }
    let spoofed = envelope("<m:GetProfilesResponse xmlns:m='urn:attacker'/>");
    assert_eq!(
        parse_profiles(spoofed.as_bytes()),
        Err(WireError::UnexpectedResponse)
    );
    let spoofed_profile = profiles(
        "<evil:Profiles xmlns:evil='urn:attacker' token='main'><t:Name>Main</t:Name></evil:Profiles>",
    );
    assert_eq!(
        parse_profiles(spoofed_profile.as_bytes()),
        Err(WireError::UnexpectedResponse)
    );
}

#[test]
fn profiles_preserve_audio_only_and_unknown_codec_without_inference() -> Result<(), WireError> {
    let content = format!(
        "{}{}{}{}<m:Profiles token='audio'><t:Name>Audio only</t:Name></m:Profiles>",
        profile("avc", "H264"),
        profile("jpeg", "JPEG"),
        profile("mpeg4", "MPEG4"),
        profile("hevc-extension", "H265")
    );
    let parsed = parse_profiles(profiles(&content).as_bytes())?;
    assert_eq!(parsed.len(), 5);
    for (index, expected) in [
        VideoEncoding::H264,
        VideoEncoding::Jpeg,
        VideoEncoding::Mpeg4,
        VideoEncoding::Unsupported,
    ]
    .into_iter()
    .enumerate()
    {
        let video = parsed[index]
            .video
            .as_ref()
            .ok_or(WireError::MissingField)?;
        assert_eq!(video.encoding, expected);
        assert_eq!((video.width, video.height), (1920, 1080));
    }
    assert_eq!(parsed[4].video, None);
    assert!(parse_profiles(profiles("").as_bytes())?.is_empty());
    assert!(!format!("{:?}", parsed[0]).contains("Main camera"));
    Ok(())
}

#[test]
fn entities_comments_and_cdata_decode_once_without_changing_token_identity() -> Result<(), WireError>
{
    let body = profiles(
        "<m:Profiles token='a&amp;b&#x3c;&#62;é'><t:Name>North<!-- boundary --><![CDATA[ & west]]>&amp;lt;</t:Name></m:Profiles>",
    );
    let parsed = parse_profiles(body.as_bytes())?;
    assert_eq!(parsed[0].token, "a&b<>é");
    assert_eq!(parsed[0].name, "North & west&lt;");
    let request = get_stream_uri_request(&parsed[0].token)?;
    assert!(String::from_utf8_lossy(request.body()).contains("a&amp;b&lt;&gt;é"));
    Ok(())
}

#[test]
fn scalar_duplicates_and_duplicate_decoded_tokens_are_rejected() {
    let duplicate_token = format!(
        "{}{}",
        profile("a&amp;b", "H264"),
        profile("a&#38;b", "H264")
    );
    assert_eq!(
        parse_profiles(profiles(&duplicate_token).as_bytes()),
        Err(WireError::DuplicateField)
    );
    let duplicate_width = profile("main", "H264").replace(
        "<t:Width>1920</t:Width>",
        "<t:Width>1920</t:Width><t:Width>1280</t:Width>",
    );
    assert_eq!(
        parse_profiles(profiles(&duplicate_width).as_bytes()),
        Err(WireError::DuplicateField)
    );
    let duplicate_endpoint = envelope(
        "<d:GetCapabilitiesResponse><d:Capabilities><t:Media><t:XAddr>http://192.0.2.7/a</t:XAddr><t:XAddr>http://192.0.2.7/b</t:XAddr></t:Media></d:Capabilities></d:GetCapabilitiesResponse>",
    );
    assert_eq!(
        parse_capabilities(duplicate_endpoint.as_bytes()),
        Err(WireError::DuplicateField)
    );
    let duplicate_uri = uri_response("rtsp://192.0.2.7/live", "false", "false", "PT0S")
        .replace("</t:Uri>", "</t:Uri><t:Uri>rtsp://192.0.2.7/other</t:Uri>");
    assert_eq!(
        parse_stream_uri(duplicate_uri.as_bytes()),
        Err(WireError::DuplicateField)
    );
}

#[test]
fn profile_count_boundary_is_complete_or_refused() -> Result<(), WireError> {
    let mut content = String::new();
    for index in 0..wire::MAX_MEDIA_PROFILES {
        content.push_str(&format!(
            "<m:Profiles token='p{index}'><t:Name>Camera</t:Name></m:Profiles>"
        ));
    }
    assert_eq!(
        parse_profiles(profiles(&content).as_bytes())?.len(),
        wire::MAX_MEDIA_PROFILES
    );
    content.push_str("<m:Profiles token='overflow'><t:Name>Camera</t:Name></m:Profiles>");
    assert_eq!(
        parse_profiles(profiles(&content).as_bytes()),
        Err(WireError::ProfileLimitExceeded)
    );
    Ok(())
}

#[test]
fn incomplete_or_unbounded_profile_scalars_are_refused() {
    let good = profile("main", "H264");
    for width in ["0", "-1", "32769", "4294967296", "NaN", "1e3", ""] {
        let bad = good.replace(
            "<t:Width>1920</t:Width>",
            &format!("<t:Width>{width}</t:Width>"),
        );
        assert_eq!(
            parse_profiles(profiles(&bad).as_bytes()),
            Err(WireError::InvalidField)
        );
    }
    for remove in [
        " token='main'",
        "<t:Name>Main camera</t:Name>",
        "<t:Encoding>H264</t:Encoding>",
        "<t:Height>1080</t:Height>",
    ] {
        assert_eq!(
            parse_profiles(profiles(&good.replace(remove, "")).as_bytes()),
            Err(WireError::MissingField)
        );
    }
    let invalid_fixed = good.replace("fixed='1'", "fixed='yes'");
    assert_eq!(
        parse_profiles(profiles(&invalid_fixed).as_bytes()),
        Err(WireError::InvalidField)
    );
}

#[test]
fn stream_uri_preserves_query_and_mandatory_lifetime() -> Result<(), WireError> {
    let bytes = uri_response(
        "rtsp://192.0.2.7:554/live%20profile?channel=1&amp;mode=main",
        "0",
        "false",
        "PT0S",
    );
    let parsed = parse_stream_uri(bytes.as_bytes())?;
    assert_eq!(
        parsed.uri,
        "rtsp://192.0.2.7:554/live%20profile?channel=1&mode=main"
    );
    assert!(parsed.is_stable());
    assert!(!format!("{parsed:?}").contains("channel"));
    for remove in [
        "<t:InvalidAfterConnect>0</t:InvalidAfterConnect>",
        "<t:InvalidAfterReboot>false</t:InvalidAfterReboot>",
        "<t:Timeout>PT0S</t:Timeout>",
    ] {
        assert_eq!(
            parse_stream_uri(bytes.replace(remove, "").as_bytes()),
            Err(WireError::MissingField)
        );
    }
    Ok(())
}

#[test]
fn reusable_uri_requires_all_zero_duration_components_and_both_false_flags() -> Result<(), WireError>
{
    for duration in ["PT0S", "P0D", "P0Y0M0DT0H0M0.000S", "P000D", "PT00H00M00S"] {
        assert!(
            parse_stream_uri(
                uri_response("rtsp://192.0.2.7/live", "false", "false", duration).as_bytes()
            )?
            .is_stable()
        );
    }
    for duration in ["PT1S", "P1M", "PT0.001S", "P0DT1H"] {
        assert!(
            !parse_stream_uri(
                uri_response("rtsp://192.0.2.7/live", "false", "false", duration).as_bytes()
            )?
            .is_stable()
        );
    }
    assert!(
        !parse_stream_uri(
            uri_response("rtsp://192.0.2.7/live", "true", "false", "PT0S").as_bytes()
        )?
        .is_stable()
    );
    assert!(
        !parse_stream_uri(uri_response("rtsp://192.0.2.7/live", "false", "1", "PT0S").as_bytes())?
            .is_stable()
    );
    for bad in [
        "P",
        "PT",
        "PT.1S",
        "PT1.S",
        "P1DT",
        "P1D1D",
        "PT1M1H",
        "P1S",
        "PT-1S",
        "-PT0S",
        "PTNaNS",
        "PT0S/secret",
        "P1.1Y",
    ] {
        assert_eq!(
            parse_stream_uri(
                uri_response("rtsp://192.0.2.7/live", "false", "false", bad).as_bytes()
            ),
            Err(WireError::InvalidField)
        );
    }
    Ok(())
}

#[test]
fn fault_codes_use_resolved_qnames_and_never_reflect_device_prose() {
    let fault = "<s:Fault xmlns:e='http://www.onvif.org/ver10/error'><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>e:InvalidArgVal</s:Value><s:Subcode><s:Value>e:NoProfile</s:Value></s:Subcode></s:Subcode></s:Code><s:Reason><s:Text xml:lang='en'>password-canary rtsp://user:secret@host/live</s:Text></s:Reason></s:Fault>";
    let expected = WireError::SoapFault(SoapFault {
        code: SoapFaultCode::Sender,
        subcode: SoapFaultSubcode::NoProfile,
    });
    assert_eq!(parse_profiles(envelope(fault).as_bytes()), Err(expected));
    assert_eq!(
        parse_soap_fault(envelope(fault).as_bytes()),
        Ok(SoapFault {
            code: SoapFaultCode::Sender,
            subcode: SoapFaultSubcode::NoProfile,
        })
    );
    assert_eq!(
        parse_soap_fault(profiles("").as_bytes()),
        Err(WireError::UnexpectedResponse)
    );
    assert!(!format!("{expected:?} {expected}").contains("canary"));
    assert!(!format!("{expected:?} {expected}").contains("secret"));
    let spoofed = fault.replace("http://www.onvif.org/ver10/error", "urn:attacker");
    assert_eq!(
        parse_profiles(envelope(&spoofed).as_bytes()),
        Err(WireError::SoapFault(SoapFault {
            code: SoapFaultCode::Sender,
            subcode: SoapFaultSubcode::Unknown
        }))
    );
    let unauthorized = fault.replace("e:NoProfile", "e:NotAuthorized");
    assert_eq!(
        parse_capabilities(envelope(&unauthorized).as_bytes()),
        Err(WireError::SoapFault(SoapFault {
            code: SoapFaultCode::Sender,
            subcode: SoapFaultSubcode::NotAuthorized
        }))
    );
}

#[test]
fn envelope_and_body_structure_are_not_searchable_wrappers() {
    let good = profiles("");
    for invalid in [
        good.replace(SOAP, "http://schemas.xmlsoap.org/soap/envelope/"),
        good.replace("</s:Body>", "<m:GetProfilesResponse/></s:Body>"),
        good.replace("</s:Envelope>", "<s:Body/></s:Envelope>"),
        good.replace("</s:Body>", "</s:Body><s:Header/>"),
        good.replace("<s:Body>", "<s:Body>unexpected prose"),
        good.replace(
            "<m:GetProfilesResponse></m:GetProfilesResponse>",
            "<m:Wrapper><m:GetProfilesResponse/></m:Wrapper>",
        ),
    ] {
        assert!(parse_profiles(invalid.as_bytes()).is_err());
    }
}

#[test]
fn required_unknown_header_and_soap_encoding_refuse() -> Result<(), WireError> {
    let good = profiles("");
    let required = good.replace(
        "<s:Body>",
        "<s:Header><x:Required xmlns:x='urn:test' s:mustUnderstand='true'/></s:Header><s:Body>",
    );
    assert_eq!(
        parse_profiles(required.as_bytes()),
        Err(WireError::UnsupportedHeader)
    );
    let optional = required.replace("mustUnderstand='true'", "mustUnderstand='false'");
    assert!(parse_profiles(optional.as_bytes())?.is_empty());
    let encoded = good.replace("<s:Body>", "<s:Body s:encodingStyle='urn:encoded'>");
    assert_eq!(
        parse_profiles(encoded.as_bytes()),
        Err(WireError::UnsupportedHeader)
    );
    Ok(())
}

#[test]
fn malformed_namespace_attributes_and_external_entities_fail_closed() {
    let good = profiles(&profile("main", "H264"));
    let malformed = [
        good.replace("token='main'", "token='main' token='other'"),
        good.replace(
            "token='main'",
            "token='main' xmlns:x='urn:dup' xmlns:y='urn:dup' x:a='1' y:a='2'",
        ),
        good.replace(
            "token='main'",
            "token='main' xmlns:x='urn:first' xmlns:x='urn:second'",
        ),
        good.replace("token='main'", "token='main' xmlns:xml='urn:spoof'"),
        good.replace(
            "token='main'",
            "token='main' xmlns:x='http://www.w3.org/XML/1998/namespace'",
        ),
        good.replace("token='main'", "token='main' xmlns:xmlns='urn:spoof'"),
        good.replace("token='main'", "token='main' xmlns:x=''"),
        good.replace("<t:Name>", "<unknown:Name>"),
        good.replace("Main camera", "&external;"),
        good.replace("Main camera", "&#0;"),
        good.replace("Main camera", "&#xD800;"),
        good.replace("Main camera", "&#x110000;"),
        good.replace("Main camera", "&#-1;"),
        good.replace("Main camera", "&#x;"),
        good.replace("Main camera", "]]>"),
        good.replace("Main camera", "bad\u{0}"),
        format!("<!DOCTYPE s:Envelope [<!ENTITY external SYSTEM 'file:///etc/passwd'>]>{good}"),
        format!("<?unhandled instruction?>{good}"),
        format!("{good}{good}"),
        format!("&#32;{good}"),
        format!("<?xml version='&#49;.0'?>{good}"),
    ];
    for bytes in malformed {
        assert!(parse_profiles(bytes.as_bytes()).is_err());
    }
    assert_eq!(parse_profiles(&[0xff, 0xfe]), Err(WireError::MalformedXml));
}

#[test]
fn bounded_xml_limits_cover_depth_nodes_attributes_and_scalar_bytes() {
    assert_eq!(
        parse_profiles(&vec![b'x'; wire::MAX_SOAP_BYTES + 1]),
        Err(WireError::InputTooLarge)
    );
    let deep = envelope(&format!("{}{}", "<m:x>".repeat(33), "</m:x>".repeat(33)));
    assert_eq!(
        parse_profiles(deep.as_bytes()),
        Err(WireError::XmlLimitExceeded)
    );
    let many = profiles(&"<m:Extension/>".repeat(4096));
    assert_eq!(
        parse_profiles(many.as_bytes()),
        Err(WireError::XmlLimitExceeded)
    );
    let attrs = (0..33).map(|i| format!(" a{i}='x'")).collect::<String>();
    let attributes = profiles(&format!("<m:Extension{attrs}/>"));
    assert_eq!(
        parse_profiles(attributes.as_bytes()),
        Err(WireError::XmlLimitExceeded)
    );
    let huge_text = profiles(&format!(
        "<m:Extension>{}</m:Extension>",
        "x".repeat(16 * 1024 + 1)
    ));
    assert_eq!(
        parse_profiles(huge_text.as_bytes()),
        Err(WireError::XmlLimitExceeded)
    );
    let huge_uri = uri_response(
        &"x".repeat(wire::MAX_URI_BYTES + 1),
        "false",
        "false",
        "PT0S",
    );
    assert_eq!(
        parse_stream_uri(huge_uri.as_bytes()),
        Err(WireError::InvalidField)
    );
}

#[test]
fn utf8_declaration_bom_and_line_endings_are_supported() -> Result<(), WireError> {
    let body = profiles("<m:Profiles token='main'><t:Name>Entrée</t:Name></m:Profiles>");
    let xml =
        format!("\u{feff}<?xml version='1.0' encoding='utf-8' standalone='yes'?>\r\n{body}\r\n");
    assert_eq!(parse_profiles(xml.as_bytes())?[0].name, "Entrée");
    let wrong_encoding = xml.replace("utf-8", "UTF-16");
    assert_eq!(
        parse_profiles(wrong_encoding.as_bytes()),
        Err(WireError::UnsupportedXml)
    );
    let wrong_version = xml.replace("version='1.0'", "version='1.1'");
    assert_eq!(
        parse_profiles(wrong_version.as_bytes()),
        Err(WireError::UnsupportedXml)
    );
    Ok(())
}

fn media2_envelope(content: &str) -> String {
    envelope(content).replace("<s:Body>", &format!("<s:Body xmlns:m2='{MEDIA2}'>"))
}

fn service(namespace: &str, uri: &str) -> String {
    format!(
        "<d:Service><d:Namespace>{namespace}</d:Namespace><d:XAddr>{uri}</d:XAddr><d:Version><t:Major>24</t:Major><t:Minor>06</t:Minor></d:Version></d:Service>"
    )
}

fn services(content: &str) -> String {
    envelope(&format!(
        "<d:GetServicesResponse>{content}</d:GetServicesResponse>"
    ))
}

fn media2_profile(token: &str, encoding: &str) -> String {
    format!(
        "<m2:Profiles token='{token}' fixed='false'><m2:Name>Private Media2 camera</m2:Name><m2:Configurations><m2:VideoEncoder token='encoder'><t:Encoding>{encoding}</t:Encoding><t:Resolution><t:Width>3840</t:Width><t:Height>2160</t:Height></t:Resolution></m2:VideoEncoder></m2:Configurations></m2:Profiles>"
    )
}

fn media2_profiles(content: &str) -> String {
    media2_envelope(&format!(
        "<m2:GetProfilesResponse>{content}</m2:GetProfilesResponse>"
    ))
}

#[test]
fn media2_requests_pin_namespace_configuration_type_and_tcp_transport() -> Result<(), WireError> {
    let request = wire::get_services_request();
    assert_eq!(
        request.action(),
        "http://www.onvif.org/ver10/device/wsdl/GetServices"
    );
    assert!(
        String::from_utf8_lossy(request.body())
            .contains("<tds:IncludeCapability>false</tds:IncludeCapability>")
    );
    let request = wire::get_media2_profiles_request();
    assert_eq!(
        request.action(),
        "http://www.onvif.org/ver20/media/wsdl/GetProfiles"
    );
    assert!(String::from_utf8_lossy(request.body()).contains("<tr2:Type>VideoEncoder</tr2:Type>"));
    let request = wire::get_media2_stream_uri_request("private<&\"'>")?;
    assert_eq!(
        request.action(),
        "http://www.onvif.org/ver20/media/wsdl/GetStreamUri"
    );
    let body = String::from_utf8_lossy(request.body());
    assert!(body.contains("<tr2:Protocol>RTSP</tr2:Protocol>"));
    assert!(body.contains("<tr2:ProfileToken>private&lt;&amp;&quot;&apos;&gt;</tr2:ProfileToken>"));
    assert!(!body.contains("StreamSetup"));
    assert!(!format!("{request:?}").contains("private"));
    assert_eq!(
        wire::get_media2_stream_uri_request(""),
        Err(WireError::InvalidField)
    );
    assert_eq!(
        wire::get_media2_stream_uri_request(&"é".repeat(65)),
        Err(WireError::InvalidField)
    );
    Ok(())
}

#[test]
fn media2_service_selection_is_exact_complete_and_never_a_route_grant() -> Result<(), WireError> {
    let uri = "http://192.0.2.9:80/onvif/private_media2";
    let inventory = services(&format!(
        "{}{}",
        service(MEDIA, "http://192.0.2.9/onvif/media1"),
        service(MEDIA2, uri)
    ));
    let selected =
        wire::parse_media2_service(inventory.as_bytes())?.ok_or(WireError::MissingField)?;
    assert_eq!(selected.xaddr, uri);
    assert_eq!(
        selected.version,
        wire::ServiceVersion {
            major: 24,
            minor: 6
        }
    );
    assert!(!format!("{selected:?}").contains("private_media2"));
    assert_eq!(
        wire::parse_media2_service(services(&service(MEDIA, uri)).as_bytes())?,
        None
    );
    assert_eq!(
        wire::parse_media2_service(services(&service(&format!("{MEDIA2}/"), uri)).as_bytes())?,
        None
    );
    // Endpoint authorization belongs to the client, never the XML parser.
    assert_eq!(
        wire::parse_media2_service(
            services(&service(MEDIA2, "https://foreign.invalid/media")).as_bytes()
        )?
        .unwrap()
        .xaddr,
        "https://foreign.invalid/media"
    );
    assert_eq!(
        wire::parse_media2_service(services("").as_bytes()),
        Err(WireError::MissingField)
    );
    Ok(())
}

#[test]
fn media2_service_spoofs_duplicates_and_overflow_refuse_the_inventory() {
    let good = service(MEDIA2, "http://192.0.2.9/onvif/media2");
    for bad in [
        good.replace("<d:Namespace>", "<t:Namespace>")
            .replace("</d:Namespace>", "</t:Namespace>"),
        good.replace("<d:XAddr>", "<t:XAddr>")
            .replace("</d:XAddr>", "</t:XAddr>"),
        good.replace("<t:Major>24</t:Major>", ""),
        good.replace("<t:Major>24</t:Major>", "<t:Major>-1</t:Major>"),
        good.replace("<t:Minor>06</t:Minor>", "<t:Minor>65536</t:Minor>"),
    ] {
        assert!(wire::parse_media2_service(services(&bad).as_bytes()).is_err());
    }
    for duplicate in [
        format!("{good}{good}"),
        good.replace(
            "</d:Namespace>",
            &format!("</d:Namespace><d:Namespace>{MEDIA}</d:Namespace>"),
        ),
    ] {
        assert_eq!(
            wire::parse_media2_service(services(&duplicate).as_bytes()),
            Err(WireError::DuplicateField)
        );
    }
    let foreign = good
        .replace("<d:Service>", "<t:Service>")
        .replace("</d:Service>", "</t:Service>");
    assert_eq!(
        wire::parse_media2_service(services(&foreign).as_bytes()),
        Err(WireError::UnexpectedResponse)
    );
    let mut content = String::new();
    for index in 0..wire::MAX_ONVIF_SERVICES {
        content.push_str(&service(
            &format!("urn:fixture:service:{index}"),
            "http://192.0.2.9/onvif/service",
        ));
    }
    assert_eq!(
        wire::parse_media2_service(services(&content).as_bytes()),
        Ok(None)
    );
    content.push_str(&good);
    assert_eq!(
        wire::parse_media2_service(services(&content).as_bytes()),
        Err(WireError::ServiceLimitExceeded)
    );
}

#[test]
fn media2_profiles_read_the_media2_configuration_shape_and_h265_vocabulary() -> Result<(), WireError>
{
    let content = format!(
        "{}{}{}{}{}<m2:Profiles token='no-video'><m2:Name>Metadata only</m2:Name></m2:Profiles>",
        media2_profile("hevc", "H265"),
        media2_profile("avc", "H264"),
        media2_profile("jpeg", "JPEG"),
        media2_profile("mpeg4", "MPV4-ES"),
        media2_profile("vendor", "vendor-private-codec")
    );
    let profiles = wire::parse_media2_profiles(media2_profiles(&content).as_bytes())?;
    assert_eq!(profiles.len(), 6);
    for (profile, expected) in profiles.iter().zip([
        VideoEncoding::H265,
        VideoEncoding::H264,
        VideoEncoding::Jpeg,
        VideoEncoding::Mpeg4,
        VideoEncoding::Unsupported,
    ]) {
        let video = profile.video.as_ref().ok_or(WireError::MissingField)?;
        assert_eq!(video.encoding, expected);
        assert_eq!((video.width, video.height), (3840, 2160));
    }
    assert_eq!(profiles[5].video, None);
    assert!(wire::parse_media2_profiles(media2_profiles("").as_bytes())?.is_empty());
    assert!(!format!("{profiles:?}").contains("Private Media2 camera"));
    Ok(())
}

#[test]
fn media2_profiles_reject_ambiguous_fields_and_do_not_infer_missing_video() -> Result<(), WireError>
{
    let good = media2_profile("main", "H265");
    for bad in [
        good.replace("<m2:Name>", "<t:Name>")
            .replace("</m2:Name>", "</t:Name>"),
        good.replace("<t:Encoding>H265</t:Encoding>", ""),
        good.replace("<t:Width>3840</t:Width>", "<t:Width>0</t:Width>"),
    ] {
        assert!(wire::parse_media2_profiles(media2_profiles(&bad).as_bytes()).is_err());
    }
    for duplicate in [
        format!("{good}{good}"),
        good.replace("</t:Width>", "</t:Width><t:Width>1920</t:Width>"),
        good.replace("</m2:Name>", "</m2:Name><m2:Name>Second</m2:Name>"),
        good.replace(
            "</m2:Configurations>",
            "</m2:Configurations><m2:Configurations/>",
        ),
    ] {
        assert_eq!(
            wire::parse_media2_profiles(media2_profiles(&duplicate).as_bytes()),
            Err(WireError::DuplicateField)
        );
    }
    let wrong_encoder_namespace = good
        .replace("<m2:VideoEncoder ", "<t:VideoEncoder ")
        .replace("</m2:VideoEncoder>", "</t:VideoEncoder>");
    assert_eq!(
        wire::parse_media2_profiles(media2_profiles(&wrong_encoder_namespace).as_bytes())?[0].video,
        None
    );
    assert_eq!(
        wire::parse_media2_profiles(profiles(&profile("main", "H264")).as_bytes()),
        Err(WireError::UnexpectedResponse)
    );
    Ok(())
}

#[test]
fn media2_profile_list_and_encoder_dimensions_obey_existing_bounds() {
    let mut content = String::new();
    for index in 0..wire::MAX_MEDIA_PROFILES {
        content.push_str(&media2_profile(&format!("p{index}"), "H265"));
    }
    assert_eq!(
        wire::parse_media2_profiles(media2_profiles(&content).as_bytes())
            .unwrap()
            .len(),
        wire::MAX_MEDIA_PROFILES
    );
    content.push_str(&media2_profile("overflow", "H265"));
    assert_eq!(
        wire::parse_media2_profiles(media2_profiles(&content).as_bytes()),
        Err(WireError::ProfileLimitExceeded)
    );
    for width in ["-1", "32769", "NaN", "4294967296", ""] {
        let bad = media2_profile("main", "H265").replace(
            "<t:Width>3840</t:Width>",
            &format!("<t:Width>{width}</t:Width>"),
        );
        assert_eq!(
            wire::parse_media2_profiles(media2_profiles(&bad).as_bytes()),
            Err(WireError::InvalidField)
        );
    }
}

#[test]
fn media2_uri_preserves_exact_query_without_inventing_media1_lifetime() -> Result<(), WireError> {
    let good = media2_envelope(
        "<m2:GetStreamUriResponse><m2:Uri>rtsp://192.0.2.9/live%20main?token=private&amp;channel=2</m2:Uri></m2:GetStreamUriResponse>",
    );
    let stream = wire::parse_media2_stream_uri(good.as_bytes())?;
    assert_eq!(
        stream.uri,
        "rtsp://192.0.2.9/live%20main?token=private&channel=2"
    );
    assert!(!format!("{stream:?}").contains("token"));
    assert_eq!(
        wire::parse_media2_stream_uri(
            good.replace("<m2:Uri>", "<t:Uri>")
                .replace("</m2:Uri>", "</t:Uri>")
                .as_bytes()
        ),
        Err(WireError::MissingField)
    );
    assert_eq!(
        wire::parse_media2_stream_uri(
            good.replace(
                "</m2:Uri>",
                "</m2:Uri><m2:Uri>rtsp://192.0.2.9/other</m2:Uri>"
            )
            .as_bytes()
        ),
        Err(WireError::DuplicateField)
    );
    assert_eq!(
        wire::parse_media2_stream_uri(
            good.replace(
                "</m2:GetStreamUriResponse>",
                "<t:Timeout>PT0S</t:Timeout></m2:GetStreamUriResponse>"
            )
            .as_bytes()
        ),
        Err(WireError::UnexpectedResponse)
    );
    assert_eq!(
        wire::parse_media2_stream_uri(
            uri_response("rtsp://192.0.2.9/live", "false", "false", "PT0S").as_bytes()
        ),
        Err(WireError::UnexpectedResponse)
    );
    Ok(())
}
