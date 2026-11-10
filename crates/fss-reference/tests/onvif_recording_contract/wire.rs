#![forbid(unsafe_code)]
//! Exact production recording wire contracts, also reusable without the native runtime.

use super::fixtures::*;
use super::wire::{
    self, AdvertisedRecordingRange, MAX_RECORDING_INFORMATION_BYTES, MAX_RECORDING_TRACKS,
    MAX_RECORDINGS, OnvifOperation, RecordingCheckError as Check, RecordingInformation,
    RecordingRangeAssessment as Assessment, RecordingTrackType, ServiceVersion,
    SoapFaultCode, SoapFaultSubcode, WireError,
};
use fss_core::ContentDigest;

type Test = Result<(), Box<dyn std::error::Error>>;

fn ns(value: &str) -> i128 {
    wire::parse_metadata_utc_nanoseconds(value).expect("fixture UTC")
}
fn request_bounds() -> (i128, i128) {
    (ns("2026-11-01T12:00:10Z"), ns("2026-11-01T12:00:20Z"))
}

#[test]
fn read_only_builders_bind_namespace_operation_transport_and_exact_escaped_token() -> Test {
    let inventory = wire::get_recordings_request();
    assert_eq!(inventory.action(), OnvifOperation::GetRecordings.action());
    assert!(std::str::from_utf8(inventory.body())?.contains("<trc:GetRecordings/>"));
    let token = " private&<>\"' ";
    let escaped = " private&amp;&lt;&gt;&quot;&apos; ";
    for request in [wire::get_recording_information_request(token)?, wire::get_replay_uri_request(token)?] {
        let body = std::str::from_utf8(request.body())?;
        assert!(body.contains(escaped));
        assert!(!request.is_event_subscription());
        assert!(!request.has_username_token());
        assert!(!body.contains("FindRecordings"));
    }
    let request = wire::get_replay_uri_request(token)?;
    let body = std::str::from_utf8(request.body())?;
    assert!(body.contains("<tt:Stream>RTP_unicast</tt:Stream>"));
    assert!(body.contains("<tt:Protocol>RTSP</tt:Protocol>"));
    for token in ["".to_owned(), "x".repeat(65), "private\ninjection".to_owned()] {
        assert!(wire::get_recording_information_request(&token).is_err());
        assert!(wire::get_replay_uri_request(&token).is_err());
    }
    Ok(())
}

#[test]
fn complete_service_inventory_selects_exact_namespaces_and_binds_original_body() -> Test {
    let body = services("127.0.0.1:8080");
    let selected = wire::parse_recording_services(body.as_bytes())?;
    assert_eq!(selected.response_body_digest, ContentDigest::sha256(body.as_bytes()));
    assert_eq!(selected.recording.as_ref().ok_or("recording")?.xaddr, "http://127.0.0.1:8080/onvif/recording_service");
    assert_eq!(selected.search.as_ref().ok_or("search")?.version, ServiceVersion { major: 2, minor: 6 });
    assert_eq!(selected.replay.as_ref().ok_or("replay")?.xaddr, "http://127.0.0.1:8080/onvif/replay_service");
    assert_ne!(selected.digest()?, selected.response_body_digest);
    let absent = service_response(&service("urn:other-service", "http://127.0.0.1:8080/onvif/other"));
    let absent = wire::parse_recording_services(absent.as_bytes())?;
    assert!(absent.recording.is_none() && absent.search.is_none() && absent.replay.is_none());
    assert!(wire::parse_recording_services(service_response("").as_bytes()).is_err());
    Ok(())
}

#[test]
fn service_duplicates_and_late_malformed_entries_refuse_the_whole_inventory() {
    let entry = service("http://www.onvif.org/ver10/replay/wsdl", "http://127.0.0.1/onvif/replay");
    assert_eq!(wire::parse_recording_services(service_response(&format!("{entry}{entry}")).as_bytes()), Err(WireError::DuplicateField));
    let malformed = service("urn:late", "http://127.0.0.1/onvif/late").replace("<tt:Major>2</tt:Major>", "");
    assert_eq!(wire::parse_recording_services(service_response(&format!("{entry}{malformed}")).as_bytes()), Err(WireError::MissingField));
    let over = (0..=wire::MAX_ONVIF_SERVICES).map(|n| service(&format!("urn:service:{n}"), "http://127.0.0.1/onvif/other")).collect::<String>();
    assert_eq!(wire::parse_recording_services(service_response(&over).as_bytes()), Err(WireError::ServiceLimitExceeded));
}

#[test]
fn inventory_retains_all_tracks_and_configuration_without_inferred_retention() -> Test {
    let tracks = format!("{}{}{}{}", configured_track(TRACK, "Video"),
        configured_track("audio", "Audio"), configured_track("metadata", "Metadata"), configured_track("extended", "Extended"));
    let body = recordings(&recording_item(TOKEN, &tracks));
    let result = wire::parse_recordings(body.as_bytes())?;
    assert_eq!(result.response_body_digest, ContentDigest::sha256(body.as_bytes()));
    assert_eq!(result.recordings.len(), 1);
    let record = &result.recordings[0];
    assert_eq!(record.token, TOKEN);
    assert_eq!(record.source.source_id, "urn:fixture:private-source");
    assert_eq!(record.maximum_retention_time, "PT0S");
    assert_eq!(record.tracks.len(), 4);
    assert_eq!(record.tracks[0].kind, RecordingTrackType::Video);
    assert_eq!(record.tracks[3].kind, RecordingTrackType::Extended);
    assert!(wire::parse_recordings(recordings("").as_bytes())?.recordings.is_empty());
    assert!(wire::parse_recordings(recordings(&recording_item(TOKEN, "")).as_bytes())?.recordings[0].tracks.is_empty());
    Ok(())
}

#[test]
fn inventory_refuses_duplicate_truncated_or_foreign_identity_fields() {
    let one = recording_item(TOKEN, &configured_track(TRACK, "Video"));
    assert_eq!(wire::parse_recordings(recordings(&format!("{one}{one}")).as_bytes()), Err(WireError::DuplicateField));
    let duplicate_tracks = format!("{}{}", configured_track(TRACK, "Video"), configured_track(TRACK, "Audio"));
    assert_eq!(wire::parse_recordings(recordings(&recording_item(TOKEN, &duplicate_tracks)).as_bytes()), Err(WireError::DuplicateField));
    let too_many = (0..=MAX_RECORDINGS).map(|n| recording_item(&format!("recording-{n}"), "")).collect::<String>();
    assert_eq!(wire::parse_recordings(recordings(&too_many).as_bytes()), Err(WireError::RecordingLimitExceeded));
    let too_many_tracks = (0..=MAX_RECORDING_TRACKS).map(|n| configured_track(&format!("track-{n}"), "Video")).collect::<String>();
    assert_eq!(wire::parse_recordings(recordings(&recording_item(TOKEN, &too_many_tracks)).as_bytes()), Err(WireError::RecordingLimitExceeded));
    let foreign = recordings(&one).replace("tt:RecordingToken", "v:RecordingToken");
    assert_eq!(wire::parse_recordings(foreign.as_bytes()), Err(WireError::MissingField));
    let missing_tracks = recordings(&one).replace(&format!("<tt:Tracks>{}</tt:Tracks>", configured_track(TRACK, "Video")), "");
    assert_eq!(wire::parse_recordings(missing_tracks.as_bytes()), Err(WireError::MissingField));
}

#[test]
fn recording_tokens_preserve_the_exact_lexeme_instead_of_trimming_identity() -> Test {
    let body = information(" private token ", &track(" private track ", "Video", Some(START), Some(END)),
        &overall(Some(START), Some(END)), "Stopped", "");
    let info = wire::parse_recording_information(body.as_bytes())?;
    assert_eq!(info.token, " private token ");
    assert_eq!(info.video_track()?.token, " private track ");
    assert_eq!(wire::parse_recordings(recordings(&recording_item(" private token ", "")).as_bytes())?.recordings[0].token, " private token ");
    Ok(())
}

#[test]
fn information_canonical_roundtrip_binds_projection_and_unprojected_response_bytes() -> Test {
    let body = info();
    let parsed = wire::parse_recording_information(body.as_bytes())?;
    let canonical = parsed.canonical_bytes()?;
    assert!(canonical.len() < MAX_RECORDING_INFORMATION_BYTES);
    assert_eq!(RecordingInformation::from_canonical_bytes(&canonical)?, parsed);
    assert_eq!(parsed.digest()?, ContentDigest::sha256(&canonical));
    assert_eq!(parsed.response_body_digest, ContentDigest::sha256(body.as_bytes()));
    let extended = body.replace("</tse:RecordingInformation>", "<v:Extension>private extension</v:Extension></tse:RecordingInformation>");
    let with_extension = wire::parse_recording_information(extended.as_bytes())?;
    assert_eq!(parsed.token, with_extension.token);
    assert_eq!(parsed.tracks, with_extension.tracks);
    assert_ne!(parsed.response_body_digest, with_extension.response_body_digest);
    assert_ne!(parsed.digest()?, with_extension.digest()?);
    Ok(())
}

#[test]
fn canonical_cold_decode_refuses_malformed_and_unbounded_projection_bytes() -> Test {
    let parsed = wire::parse_recording_information(info().as_bytes())?;
    let bytes = parsed.canonical_bytes()?;
    let mut appended = bytes.clone(); appended.push(0);
    assert!(RecordingInformation::from_canonical_bytes(&appended).is_err());
    assert!(RecordingInformation::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert_eq!(RecordingInformation::from_canonical_bytes(&vec![0; MAX_RECORDING_INFORMATION_BYTES + 1]), Err(WireError::InputTooLarge));
    let mut wrong_version = bytes;
    let at = 8 + wire::RECORDING_INFORMATION_DOMAIN.len();
    wrong_version[at..at + 4].copy_from_slice(&2_u32.to_be_bytes());
    assert_eq!(RecordingInformation::from_canonical_bytes(&wrong_version), Err(WireError::InvalidField));
    let mut duplicate = parsed.clone(); duplicate.tracks.push(duplicate.tracks[0].clone());
    assert_eq!(duplicate.canonical_bytes(), Err(WireError::DuplicateField));
    let mut oversized = parsed; oversized.source.name = "x".repeat(wire::MAX_RECORDING_DESCRIPTION_BYTES + 1);
    assert_eq!(oversized.canonical_bytes(), Err(WireError::InvalidField));
    Ok(())
}

#[test]
fn range_checks_preserve_unknowns_refuse_every_known_edge_and_never_clip() -> Test {
    let parsed = wire::parse_recording_information(info().as_bytes())?;
    let (start, end) = request_bounds();
    assert_eq!(parsed.validate_requested_bounds(start, end)?, Assessment::WithinAdvertisedBounds);
    assert_eq!(parsed.validate_requested_bounds(ns(START) - 1, end), Err(Check::OutsideAdvertisedBounds));
    assert_eq!(parsed.validate_requested_bounds(start, ns(END) + 1), Err(Check::OutsideAdvertisedBounds));
    assert_eq!(parsed.validate_requested_bounds(ns(END) + 1, ns(END) + 2), Err(Check::OutsideAdvertisedBounds));
    let missing = information(TOKEN, &track(TRACK, "Video", Some(START), None), "", "Stopped", "");
    let missing = wire::parse_recording_information(missing.as_bytes())?;
    assert_eq!(missing.range, AdvertisedRecordingRange::default());
    assert_eq!(missing.validate_requested_bounds(start, end)?, Assessment::Unknown);
    assert_eq!(missing.validate_requested_bounds(ns(START) - 1, end), Err(Check::OutsideAdvertisedBounds));
    assert_eq!(missing.video_track()?.range.latest_ns, None);
    assert_eq!(parsed.validate_requested_bounds(end, start), Err(Check::InvalidRequestedBounds));
    Ok(())
}

#[test]
fn advertised_history_is_not_limited_to_request_duration_and_equal_extrema_are_observations() -> Test {
    let body = information(TOKEN, &track(TRACK, "Video", Some("2026-01-01T00:00:00Z"), Some(END)),
        &overall(Some("2026-01-01T00:00:00Z"), Some(END)), "Stopped", "");
    let parsed = wire::parse_recording_information(body.as_bytes())?;
    let (start, end) = request_bounds();
    assert_eq!(parsed.validate_requested_bounds(start, end)?, Assessment::WithinAdvertisedBounds);
    let point = information(TOKEN, &track(TRACK, "Video", Some(START), Some(START)),
        &overall(Some(START), Some(START)), "Stopped", "");
    let point = wire::parse_recording_information(point.as_bytes())?;
    assert_eq!(point.validate_requested_bounds(ns(START), ns(START) + 1), Err(Check::OutsideAdvertisedBounds));
    Ok(())
}

#[test]
fn contradictory_or_ambiguous_information_cannot_acquire_replay_selection() -> Test {
    let (start, end) = request_bounds();
    for (tracks, bounds) in [
        (track(TRACK, "Video", Some(END), Some(START)), overall(Some(START), Some(END))),
        (track(TRACK, "Video", Some("2026-10-31T12:00:00Z"), Some(END)), overall(Some(START), Some(END))),
        (track(TRACK, "Video", Some(START), Some(END)), overall(Some(END), Some(START))),
    ] {
        let parsed = wire::parse_recording_information(information(TOKEN, &tracks, &bounds, "Stopped", "").as_bytes())?;
        assert_eq!(parsed.validate_requested_bounds(start, end), Err(Check::ContradictoryAdvertisedBounds));
    }
    let tracks = format!("{}{}", track("one", "Video", Some(START), Some(END)), track("two", "Video", Some(START), Some(END)));
    let parsed = wire::parse_recording_information(information(TOKEN, &tracks, "", "Stopped", "").as_bytes())?;
    assert_eq!(parsed.validate_requested_bounds(start, end), Err(Check::AmbiguousVideoTracks));
    let parsed = wire::parse_recording_information(information(TOKEN, &track("audio", "Audio", None, None), "", "Stopped", "").as_bytes())?;
    assert_eq!(parsed.validate_requested_bounds(start, end), Err(Check::NoVideoTrack));
    for status in ["Removing", "Removed"] {
        let parsed = wire::parse_recording_information(information(TOKEN, &track(TRACK, "Video", None, None), "", status, "").as_bytes())?;
        assert_eq!(parsed.validate_requested_bounds(start, end), Err(Check::RecordingUnavailable));
    }
    Ok(())
}

#[test]
fn malformed_times_and_duplicate_fields_are_distinct_from_missing_observations() {
    for body in [
        info().replace(START, "2026-11-01T12:00:00+00:00"),
        info().replace(START, "2026-02-30T12:00:00Z"),
        info().replace("</tt:RecordingToken>", &format!("</tt:RecordingToken><tt:RecordingToken>{TOKEN}</tt:RecordingToken>")),
        info().replace("</tt:TrackToken>", &format!("</tt:TrackToken><tt:TrackToken>{TRACK}</tt:TrackToken>")),
        info().replace("tt:RecordingToken", "v:RecordingToken"),
        info().replace("<tt:RecordingStatus>Stopped</tt:RecordingStatus>", "<tt:RecordingStatus>VendorGuess</tt:RecordingStatus>"),
    ] {
        assert!(wire::parse_recording_information(body.as_bytes()).is_err());
    }
}

#[test]
fn replay_uri_has_no_fabricated_lifetime_and_faults_remain_typed_and_redacted() -> Test {
    let body = replay_uri(URI);
    let parsed = wire::parse_replay_uri(body.as_bytes())?;
    assert_eq!(parsed.uri, URI);
    assert_eq!(parsed.response_body_digest, ContentDigest::sha256(body.as_bytes()));
    let lifetime = body.replace("</trp:GetReplayUriResponse>", "<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect></trp:GetReplayUriResponse>");
    assert_eq!(wire::parse_replay_uri(lifetime.as_bytes()), Err(WireError::UnexpectedResponse));
    for (name, expected) in [
        ("NoRecording", SoapFaultSubcode::NoRecording),
        ("InvalidToken", SoapFaultSubcode::InvalidToken),
        ("InvalidStreamSetup", SoapFaultSubcode::InvalidStreamSetup),
        ("StreamConflict", SoapFaultSubcode::StreamConflict),
    ] {
        let parsed = wire::parse_soap_fault(fault(name).as_bytes())?;
        assert_eq!(parsed.code, SoapFaultCode::Sender);
        assert_eq!(parsed.subcode, expected);
        assert!(!format!("{:?}", WireError::SoapFault(parsed)).contains("private-host"));
    }
    Ok(())
}

#[test]
fn private_descriptions_tokens_and_uris_never_appear_in_debug_diagnostics() -> Test {
    let info = wire::parse_recording_information(info().as_bytes())?;
    let list = wire::parse_recordings(recordings(&recording_item(TOKEN, &configured_track(TRACK, "Video"))).as_bytes())?;
    let uri = wire::parse_replay_uri(replay_uri(URI).as_bytes())?;
    let services = wire::parse_recording_services(services("127.0.0.1:8080").as_bytes())?;
    let output = format!("{info:?} {:?} {:?} {list:?} {:?} {uri:?} {services:?}", info.source, info.tracks, list.recordings);
    for private in [TOKEN, TRACK, "Private Camera", "Private recording", "private.invalid", URI, "127.0.0.1:8080"] {
        assert!(!output.contains(private), "private metadata escaped Debug");
    }
    Ok(())
}
