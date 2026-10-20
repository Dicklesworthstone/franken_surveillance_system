#![forbid(unsafe_code)]

use super::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mdns_query_roundtrip_shape() {
    let q = build_mdns_query(&["_rtsp._tcp", "_onvif._tcp"], 7);
    // header: id, flags, QDCOUNT=2, AN/NS/AR=0
    assert_eq!(&q[0..2], &7u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([q[4], q[5]]), 2);
    assert_eq!(&q[6..12], &[0u8; 6]);
    // first question: 5_rtsp 4_tcp 5_local root PTR IN
    assert_eq!(&q[12..23], b"\x05_rtsp\x04_tcp");
    assert_eq!(&q[23..29], b"\x05local");
    assert_eq!(q[29], 0); // root
    assert_eq!(&q[30..32], &12u16.to_be_bytes()); // PTR
    assert_eq!(&q[32..34], &1u16.to_be_bytes()); // IN
}

#[test]
fn mdns_response_parse_with_compression() -> Test {
    // Synthetic response: 1 answer, PTR, compressed name+target.
    let mut p = Vec::new();
    p.extend_from_slice(&1u16.to_be_bytes()); // id
    p.extend_from_slice(&0x8400u16.to_be_bytes()); // response
    p.extend_from_slice(&0u16.to_be_bytes()); // qd
    p.extend_from_slice(&1u16.to_be_bytes()); // an
    p.extend_from_slice(&0u16.to_be_bytes()); // ns
    p.extend_from_slice(&0u16.to_be_bytes()); // ar
    let name_off = p.len();
    for label in ["_rtsp", "_tcp", "local"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&12u16.to_be_bytes()); // PTR
    p.extend_from_slice(&1u16.to_be_bytes()); // class
    p.extend_from_slice(&4500u32.to_be_bytes()); // ttl
    // rdata: pointer back to name
    p.extend_from_slice(&2u16.to_be_bytes());
    let ptr = ((0xC000 | name_off) as u16).to_be_bytes();
    p.extend_from_slice(&ptr);
    let answers = parse_mdns_response(&p)?;
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].name, "_rtsp._tcp.local");
    assert_eq!(answers[0].rr_type, 12);
    assert_eq!(answers[0].rdata, "_rtsp._tcp.local");
    Ok(())
}

#[test]
fn mdns_short_packet_refused() {
    assert!(matches!(
        parse_mdns_response(&[0u8; 8]),
        Err(StandardsError::ShortPacket)
    ));
}

#[test]
fn ssdp_build_and_parse() -> Test {
    let msg = build_msearch("ssdp:all", 2);
    let text = String::from_utf8(msg)?;
    assert!(text.contains("M-SEARCH * HTTP/1.1"));
    assert!(text.contains("ST: ssdp:all"));
    let resp = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: eeroOS UPnP/1.0\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.4.1:5000/desc.xml\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n";
    let parsed =
        parse_ssdp_response("192.168.4.1", resp).ok_or("valid SSDP fixture was refused")?;
    assert_eq!(parsed.server, "eeroOS UPnP/1.0");
    assert_eq!(parsed.st, "upnp:rootdevice");
    assert_eq!(parsed.location, "http://192.168.4.1:5000/desc.xml");
    assert_eq!(parsed.usn, "uuid:abc::upnp:rootdevice");
    // non-200 ignored
    assert!(parse_ssdp_response("x", b"HTTP/1.1 404 Not Found\r\n\r\n").is_none());
    Ok(())
}

#[test]
fn wsd_probe_and_parse() -> Test {
    let probe = build_wsdiscovery_probe();
    let text = String::from_utf8(probe)?;
    assert!(text.contains("dn:NetworkVideoTransmitter"));
    let match_xml = b"<?xml version=\"1.0\"?><s:Envelope><s:Body><d:ProbeMatch><d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs><d:Scopes>onvif://www.onvif.org/Profile/Streaming</d:Scopes><d:Types>dn:NetworkVideoTransmitter</d:Types></d:ProbeMatch></s:Body></s:Envelope>";
    let m = parse_wsd_match("192.168.1.50", match_xml)
        .ok_or("valid WS-Discovery fixture was refused")?;
    assert_eq!(m.xaddrs, vec!["http://192.168.1.50/onvif/device_service"]);
    assert_eq!(m.types, vec!["dn:NetworkVideoTransmitter"]);
    assert!(m.scopes.iter().any(|s| s.contains("Streaming")));
    // non-match ignored
    assert!(parse_wsd_match("x", b"<a/>").is_none());
    Ok(())
}

#[test]
fn camera_types_registered() {
    assert!(MDNS_CAMERA_TYPES.contains(&"_onvif._tcp"));
    assert!(MDNS_CAMERA_TYPES.contains(&"_rtsp._tcp"));
    assert!(MDNS_CAMERA_TYPES.len() <= 16);
}

fn header_packet(questions: u16, answers: u16, authority: u16, additional: u16) -> Vec<u8> {
    [7, 0x8400, questions, answers, authority, additional]
        .into_iter()
        .flat_map(u16::to_be_bytes)
        .collect()
}

fn name_bytes(labels: &[&[u8]]) -> Test<Vec<u8>> {
    let mut out = Vec::new();
    for label in labels {
        out.push(u8::try_from(label.len())?);
        out.extend_from_slice(label);
    }
    out.push(0);
    Ok(out)
}

fn pointer(offset: usize) -> Test<[u8; 2]> {
    Ok((0xc000 | u16::try_from(offset)?).to_be_bytes())
}

fn add_record(
    packet: &mut Vec<u8>,
    name: &[u8],
    kind: u16,
    class: u16,
    rdata: &[u8],
) -> Test<usize> {
    packet.extend_from_slice(name);
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&class.to_be_bytes());
    packet.extend_from_slice(&120u32.to_be_bytes());
    packet.extend_from_slice(&u16::try_from(rdata.len())?.to_be_bytes());
    let offset = packet.len();
    packet.extend_from_slice(rdata);
    Ok(offset)
}

fn service_packet() -> Test<Vec<u8>> {
    let mut packet = header_packet(1, 1, 0, 2);
    let question = packet.len();
    packet.extend_from_slice(&name_bytes(&[b"_rtsp", b"_tcp", b"local"])?);
    packet.extend_from_slice(&12u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    let mut instance = vec![6];
    instance.extend_from_slice(b"Camera");
    instance.extend_from_slice(&pointer(question)?);
    let instance_offset = add_record(&mut packet, &pointer(question)?, 12, 1, &instance)?;
    let mut service = [0, 1, 8554]
        .into_iter()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    service.extend_from_slice(&name_bytes(&[b"camera", b"local"])?);
    let target_offset = add_record(
        &mut packet,
        &pointer(instance_offset)?,
        33,
        0x8001,
        &service,
    )? + 6;
    add_record(
        &mut packet,
        &pointer(target_offset)?,
        1,
        0x8001,
        &[192, 168, 4, 44],
    )?;
    Ok(packet)
}

#[test]
fn mdns_service_chain_uses_compressed_owners_and_additional_records() -> Test {
    let answers = parse_mdns_response(&service_packet()?)?;
    assert_eq!(answers.len(), 3);
    assert_eq!(answers[0].name, "_rtsp._tcp.local");
    assert_eq!(answers[0].rdata, "Camera._rtsp._tcp.local");
    assert_eq!(answers[1].name, "Camera._rtsp._tcp.local");
    assert_eq!(answers[1].rdata, "camera.local");
    assert_eq!(answers[1].srv_port, Some(8554));
    assert_eq!(answers[2].name, "camera.local");
    assert_eq!(answers[2].rdata, "192.168.4.44");
    assert_eq!(answers[2].srv_port, None);
    Ok(())
}

#[test]
fn mdns_authority_records_are_retained_without_becoming_answers_to_other_classes() -> Test {
    let name = name_bytes(&[b"camera", b"local"])?;
    let mut packet = header_packet(0, 0, 2, 0);
    add_record(&mut packet, &name, 1, 1, &[192, 168, 4, 44])?;
    add_record(&mut packet, &pointer(12)?, 1, 3, b"not an IN address")?;
    let answers = parse_mdns_response(&packet)?;
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].rdata, "192.168.4.44");
    Ok(())
}

#[test]
fn compressed_name_preserves_the_original_cursor_after_a_literal_prefix() -> Test {
    let mut packet = vec![0; 12];
    packet.extend_from_slice(&name_bytes(&[b"local"])?);
    let offset = packet.len();
    packet.extend_from_slice(b"\x03cam");
    packet.extend_from_slice(&pointer(12)?);
    packet.extend_from_slice(b"unrelated following bytes");
    assert_eq!(read_name(&packet, offset)?, ("cam.local".to_owned(), 6));
    Ok(())
}

#[test]
fn mdns_rejects_queries_errors_truncation_and_excess_counts_before_records() -> Test {
    let packet = service_packet()?;
    for flags in [0u16, 0x8403, 0x8600, 0x8c00] {
        let mut bad = packet.clone();
        bad[2..4].copy_from_slice(&flags.to_be_bytes());
        assert!(parse_mdns_response(&bad).is_err(), "flags {flags:x}");
    }
    assert!(parse_mdns_response(&header_packet(17, 0, 0, 0)).is_err());
    assert!(parse_mdns_response(&header_packet(0, 1, 128, 128)).is_err());
    assert!(parse_mdns_response(&vec![0; MAX_PACKET_BYTES + 1]).is_err());
    for len in 0..packet.len() {
        assert!(parse_mdns_response(&packet[..len]).is_err(), "prefix {len}");
    }
    Ok(())
}

#[test]
fn mdns_rdata_name_cannot_read_into_the_following_record() -> Test {
    let mut packet = header_packet(0, 1, 0, 0);
    let offset = add_record(&mut packet, &name_bytes(&[b"local"])?, 12, 1, &pointer(12)?)?;
    packet[offset - 2..offset].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(parse_mdns_response(&packet), Err(StandardsError::Malformed));
    let mut packet = header_packet(0, 1, 0, 0);
    add_record(
        &mut packet,
        &name_bytes(&[b"camera", b"_rtsp", b"_tcp", b"local"])?,
        33,
        1,
        &[0; 6],
    )?;
    assert_eq!(parse_mdns_response(&packet), Err(StandardsError::Malformed));
    Ok(())
}

#[test]
fn malformed_additional_record_rejects_whole_response() -> Test {
    let mut packet = service_packet()?;
    packet.pop();
    assert!(parse_mdns_response(&packet).is_err());
    let mut packet = service_packet()?;
    packet.push(0);
    assert_eq!(parse_mdns_response(&packet), Err(StandardsError::Malformed));
    Ok(())
}

#[test]
fn mdns_names_preserve_label_boundaries_and_arbitrary_octets() -> Test {
    let mut packet = vec![0; 12];
    packet.extend_from_slice(&name_bytes(&[b"Fake._rtsp", b"_tcp", b"local"])?);
    assert_eq!(read_name(&packet, 12)?.0, "Fake\\._rtsp._tcp.local");
    let offset = packet.len();
    packet.extend_from_slice(&name_bytes(&[b"cam\\one", &[0, 255, b' '], b"local"])?);
    assert_eq!(
        read_name(&packet, offset)?.0,
        "cam\\\\one.\\000\\255\\032.local"
    );
    Ok(())
}

#[test]
fn mdns_name_expansion_and_compression_are_bounded() -> Test {
    let long = [b'a'; 63];
    let exact = [b'b'; 61];
    let mut packet = vec![0; 12];
    packet.extend_from_slice(&name_bytes(&[&long, &long, &long, &exact])?);
    assert_eq!(read_name(&packet, 12)?.1, 255);
    let mut packet = vec![0; 12];
    packet.extend_from_slice(&name_bytes(&[&long, &long, &long, &long])?);
    assert_eq!(read_name(&packet, 12), Err(StandardsError::Malformed));
    for bytes in [
        vec![0x40, 0],
        vec![0x80, 0],
        vec![0xc0, 12],
        vec![0xc0, 15],
        vec![0xff, 0xff],
        vec![0xc0, 0],
    ] {
        let mut packet = vec![0; 12];
        packet.extend_from_slice(&bytes);
        assert!(read_name(&packet, 12).is_err(), "{bytes:?}");
    }
    Ok(())
}

#[test]
fn mdns_query_refuses_oversize_or_malformed_names_without_truncation() {
    assert!(build_mdns_query(&[], 7).is_empty());
    assert!(build_mdns_query(&["_rtsp._tcp"; 17], 7).is_empty());
    assert!(build_mdns_query(&[&"x".repeat(64)], 7).is_empty());
    assert!(build_mdns_query(&["_rtsp.._tcp"], 7).is_empty());
    assert!(build_mdns_query(&["_rtsp._tcp.."], 7).is_empty());
    assert_eq!(
        build_mdns_query(&["_rtsp._tcp.local."], 7),
        build_mdns_query(&["_rtsp._tcp"], 7)
    );
}

#[test]
fn mdns_observation_binds_sender_port_and_query_id_not_advertised_address() -> Test {
    let packet = service_packet()?;
    let sender = SocketAddr::from(([192, 168, 4, 2], 5353));
    let parsed =
        parse_mdns_datagram(sender, 7, &packet).ok_or("valid mDNS datagram was refused")?;
    assert_eq!(parsed.responder, Ipv4Addr::new(192, 168, 4, 2));
    assert_eq!(parsed.answers[2].rdata, "192.168.4.44");
    assert!(parse_mdns_datagram(sender, 8, &packet).is_none());
    assert!(parse_mdns_datagram(SocketAddr::from(([192, 168, 4, 2], 1234)), 7, &packet).is_none());
    assert!(parse_mdns_datagram(sender, 7, &header_packet(0, 0, 0, 0)).is_none());
    Ok(())
}

#[test]
fn collector_bounds_malformed_and_oversized_traffic_without_sockets() {
    let cancel = AtomicBool::new(false);
    let mut received = 0;
    let mut parsed = 0;
    let result = collect_datagrams(
        1,
        &cancel,
        |buf| {
            received += 1;
            buf[0] = 0;
            Ok((1, SocketAddr::from(([192, 168, 4, 1], 5353))))
        },
        |_, _| {
            parsed += 1;
            None::<()>
        },
    );
    assert!(result.is_empty());
    assert_eq!(received, MAX_RECEIVE_ATTEMPTS);
    assert_eq!(parsed, MAX_RECEIVE_ATTEMPTS);
    let mut oversized_parses = 0;
    let result: Vec<()> = collect_datagrams(
        1,
        &cancel,
        |buf| Ok((buf.len(), SocketAddr::from(([192, 168, 4, 1], 5353)))),
        |_, _| {
            oversized_parses += 1;
            None
        },
    );
    assert_eq!(oversized_parses, 0);
    assert!(result.is_empty());
}

#[test]
fn collector_refuses_precancelled_and_unbounded_windows_before_receive() {
    let cancelled = AtomicBool::new(true);
    let active = AtomicBool::new(false);
    for (seconds, cancel) in [(1, &cancelled), (0, &active), (u64::MAX, &active)] {
        let mut receives = 0;
        let mut parses = 0;
        let result: Vec<()> = collect_datagrams(
            seconds,
            cancel,
            |_| {
                receives += 1;
                Ok((0, SocketAddr::from(([192, 168, 4, 1], 5353))))
            },
            |_, _| {
                parses += 1;
                None
            },
        );
        assert_eq!(receives, 0);
        assert_eq!(parses, 0);
        assert!(result.is_empty());
        assert!(mdns_observe(Ipv4Addr::UNSPECIFIED, &["_rtsp._tcp"], seconds, cancel).is_empty());
        assert!(ssdp_probe(Ipv4Addr::UNSPECIFIED, seconds, cancel).is_empty());
        assert!(wsdiscovery_probe(Ipv4Addr::UNSPECIFIED, seconds, cancel).is_empty());
    }
}

#[test]
fn ssdp_status_and_wsdiscovery_matches_require_exact_tokens() {
    assert!(parse_ssdp_response("192.168.4.2", b"HTTP/1.1 2000 WRONG\r\n\r\n").is_none());
    for xml in [
        b"<d:ProbeMatches>no match</d:ProbeMatches>".as_slice(),
        b"<d:ProbeMatch_fake><d:Types>dn:NetworkVideoTransmitter</d:Types></d:ProbeMatch_fake>"
            .as_slice(),
        b"<d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types>".as_slice(),
    ] {
        assert!(parse_wsd_match("192.168.4.2", xml).is_none());
    }
    let mut advert = WsdMatch {
        ip: "192.168.4.2".to_owned(),
        xaddrs: Vec::new(),
        scopes: Vec::new(),
        types: vec!["fake:NotNetworkVideoTransmitter".to_owned()],
    };
    assert!(!advert.is_onvif_camera());
    advert.types = vec!["dn:NetworkVideoTransmitterExtra".to_owned()];
    assert!(!advert.is_onvif_camera());
    advert.types = vec!["dn:Other dn:NetworkVideoTransmitter".to_owned()];
    assert!(advert.is_onvif_camera());
    advert.types.clear();
    advert.scopes = vec!["https://fake/Profile/Streaming".to_owned()];
    assert!(!advert.is_onvif_camera());
    advert.scopes = vec!["onvif://www.onvif.org/Profile/Streaming".to_owned()];
    assert!(advert.is_onvif_camera());
}

#[test]
fn collector_honors_cancellation_during_receive_before_retaining_data() {
    let cancel = AtomicBool::new(false);
    let mut receives = 0;
    let mut parses = 0;
    let result: Vec<()> = collect_datagrams(
        1,
        &cancel,
        |_| {
            receives += 1;
            cancel.store(true, Ordering::Relaxed);
            Ok((0, SocketAddr::from(([192, 168, 4, 1], 5353))))
        },
        |_, _| {
            parses += 1;
            None
        },
    );
    assert_eq!(receives, 1);
    assert_eq!(parses, 0);
    assert!(result.is_empty());
}

#[test]
fn mdns_txt_character_strings_enforce_each_declared_length() -> Test {
    let mut packet = header_packet(0, 1, 0, 0);
    add_record(
        &mut packet,
        &name_bytes(&[b"Camera", b"_rtsp", b"_tcp", b"local"])?,
        16,
        1,
        b"\x03one\x03two",
    )?;
    let records = parse_mdns_response(&packet)?;
    assert_eq!(records[0].rdata, "one two");
    packet.pop();
    assert!(parse_mdns_response(&packet).is_err());
    let mut packet = header_packet(0, 1, 0, 0);
    add_record(&mut packet, &name_bytes(&[b"local"])?, 16, 1, b"\xffshort")?;
    assert_eq!(parse_mdns_response(&packet), Err(StandardsError::Malformed));
    Ok(())
}
