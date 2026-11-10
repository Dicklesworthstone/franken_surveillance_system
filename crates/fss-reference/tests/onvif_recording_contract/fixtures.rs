#![forbid(unsafe_code)]
//! Synthetic SOAP fixtures shared by the exact production-wire and native-client contracts.

pub(super) const TOKEN: &str = "private-recording-1";
pub(super) const TRACK: &str = "private-video-1";
pub(super) const URI: &str = "rtsp://127.0.0.1:554/recordings/1?private=fixture%3Dvalue";
pub(super) const START: &str = "2026-11-01T12:00:00Z";
pub(super) const END: &str = "2026-11-01T12:01:00Z";

pub(super) fn soap(body: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trc="http://www.onvif.org/ver10/recording/wsdl" xmlns:tse="http://www.onvif.org/ver10/search/wsdl" xmlns:trp="http://www.onvif.org/ver10/replay/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:v="urn:fixture:vendor"><s:Body>{body}</s:Body></s:Envelope>"#
    )
}
pub(super) fn service(namespace: &str, xaddr: &str) -> String {
    format!(r#"<tds:Service><tds:Namespace>{namespace}</tds:Namespace><tds:XAddr>{xaddr}</tds:XAddr><tds:Version><tt:Major>2</tt:Major><tt:Minor>6</tt:Minor></tds:Version></tds:Service>"#)
}
pub(super) fn service_response(entries: &str) -> String {
    soap(&format!("<tds:GetServicesResponse>{entries}</tds:GetServicesResponse>"))
}
pub(super) fn services(authority: &str) -> String {
    service_response(&format!("{}{}{}",
        service("http://www.onvif.org/ver10/recording/wsdl", &format!("http://{authority}/onvif/recording_service")),
        service("http://www.onvif.org/ver10/search/wsdl", &format!("http://{authority}/onvif/search_service")),
        service("http://www.onvif.org/ver10/replay/wsdl", &format!("http://{authority}/onvif/replay_service")),
    ))
}
pub(super) fn source() -> &'static str {
    "<tt:Source><tt:SourceId>urn:fixture:private-source</tt:SourceId><tt:Name>Private Camera</tt:Name><tt:Location>Private Gate</tt:Location><tt:Description>Private description</tt:Description><tt:Address>rtsp://private.invalid/original</tt:Address><tt:VideoSourceToken>source-token</tt:VideoSourceToken></tt:Source>"
}
pub(super) fn configured_track(token: &str, kind: &str) -> String {
    format!("<tt:Track><tt:TrackToken>{token}</tt:TrackToken><tt:Configuration><tt:TrackType>{kind}</tt:TrackType><tt:Description>Private track</tt:Description></tt:Configuration></tt:Track>")
}
pub(super) fn recording_item(token: &str, tracks: &str) -> String {
    format!("<trc:RecordingItem><tt:RecordingToken>{token}</tt:RecordingToken><tt:Configuration>{}<tt:Content>Private recording</tt:Content><tt:MaximumRetentionTime>PT0S</tt:MaximumRetentionTime></tt:Configuration><tt:Tracks>{tracks}</tt:Tracks></trc:RecordingItem>", source())
}
pub(super) fn recordings(items: &str) -> String {
    soap(&format!("<trc:GetRecordingsResponse>{items}</trc:GetRecordingsResponse>"))
}
pub(super) fn track(token: &str, kind: &str, first: Option<&str>, last: Option<&str>) -> String {
    let first = first.map(|s| format!("<tt:DataFrom>{s}</tt:DataFrom>")).unwrap_or_default();
    let last = last.map(|s| format!("<tt:DataTo>{s}</tt:DataTo>")).unwrap_or_default();
    format!("<tt:Track><tt:TrackToken>{token}</tt:TrackToken><tt:TrackType>{kind}</tt:TrackType><tt:Description>Private track</tt:Description>{first}{last}</tt:Track>")
}
pub(super) fn overall(first: Option<&str>, last: Option<&str>) -> String {
    format!("{}{}",
        first.map(|s| format!("<tt:EarliestRecording>{s}</tt:EarliestRecording>")).unwrap_or_default(),
        last.map(|s| format!("<tt:LatestRecording>{s}</tt:LatestRecording>")).unwrap_or_default(),
    )
}
pub(super) fn information(token: &str, tracks: &str, bounds: &str, status: &str, extension: &str) -> String {
    soap(&format!("<tse:GetRecordingInformationResponse><tse:RecordingInformation><tt:RecordingToken>{token}</tt:RecordingToken>{}{bounds}<tt:Content>Private recording</tt:Content>{tracks}<tt:RecordingStatus>{status}</tt:RecordingStatus>{extension}</tse:RecordingInformation></tse:GetRecordingInformationResponse>", source()))
}
pub(super) fn info() -> String {
    information(TOKEN, &track(TRACK, "Video", Some(START), Some(END)),
        &overall(Some(START), Some(END)), "Stopped", "")
}
pub(super) fn replay_uri(uri: &str) -> String {
    soap(&format!("<trp:GetReplayUriResponse><trp:Uri>{}</trp:Uri></trp:GetReplayUriResponse>", uri.replace('&', "&amp;")))
}
pub(super) fn fault(subcode: &str) -> String {
    soap(&format!("<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>ter:InvalidArgVal</s:Value><s:Subcode><s:Value>ter:{subcode}</s:Value></s:Subcode></s:Subcode></s:Code><s:Reason><s:Text xml:lang=\"en\">private-host-and-token-must-never-escape</s:Text></s:Reason></s:Fault>"))
}
