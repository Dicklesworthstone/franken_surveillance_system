#![forbid(unsafe_code)]
//! Strict operator input only; JSON never supplies current authority or a trusted picture boundary.
use super::*;
use fss_cli::json_input::{self, Value};
use fss_core::{SensorId, StreamId};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_packet::hevc::{HevcAssemblyLimits, HevcConfiguration, HevcConfigurationLimits};
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_publication::LocalPublicationLimits;
use fss_reference::rtsp::datagram_archive::{DatagramArchiveLimits, DatagramPin, DatagramScope};
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::HevcRecordingReplaySpec;
use fss_reference::rtsp::datagram_reconstruction::hevc::{HevcReplayBounds, HevcReplaySpec};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::hevc::HevcRecordingTiming;
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_recipe::hevc::authoring::TimingInput;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(super) struct Options {
    pub root: PathBuf,
    pub draft: PathBuf,
    pub draft_id: ContentDigest,
    pub approval: Option<ContentDigest>,
    pub timeout: Duration,
    pub steps: u64,
    pub work: u64,
    pub draft_bytes: usize,
    pub timings: usize,
    pub windows: usize,
    pub output_bytes: u64,
    pub source: DatagramArchiveLimits,
    pub storage: LocalPublicationLimits,
}
impl Options {
    pub fn bounds(&self, clock: &Clock) -> Result<HevcReplayBounds> {
        Ok(HevcReplayBounds {
            max_source_bytes: self.source.max_payload_bytes,
            max_steps: self.steps,
            deadline_ns: clock.deadline()?,
        })
    }
}
pub(super) fn options(args: &[OsString]) -> Result<Options> {
    if !handles(args) || args.len() > 65 || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
        return Err(malformed("invalid authoring command or argument bounds"));
    }
    let allowed = [
        "--root",
        "--draft",
        "--draft-id",
        "--commit",
        "--approve-recipe",
        "--timeout-ms",
        "--max-steps",
        "--max-work",
        "--max-draft-bytes",
        "--max-timings",
        "--max-datagrams",
        "--max-source-bytes",
        "--max-windows",
        "--max-output-bytes",
        "--max-roots",
        "--max-scan-roots",
        "--max-objects",
        "--max-object-bytes",
        "--max-total-bytes",
    ];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !allowed.contains(&key) {
            return Err(argument(ERR_CLI_UNKNOWN_OPTION, "unknown authoring option"));
        }
        if values.contains_key(key) {
            return Err(argument(ERR_CLI_DUPLICATE_OPTION, "duplicate option"));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "missing option value"))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required authoring option missing"))
    };
    let text = |key: &str| {
        required(key)?
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "identity must be UTF-8"))
    };
    let number = |key: &str, default: u64, min: u64, max: u64| -> Result<u64> {
        let n = if values.contains_key(key) {
            let s = text(key)?;
            if !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed("expected unsigned decimal bound"));
            }
            s.parse::<u64>()
                .map_err(|_| malformed("integer overflow"))?
        } else {
            default
        };
        if !(min..=max).contains(&n) {
            return Err(malformed("numeric bound exceeded"));
        }
        Ok(n)
    };
    let approval = if values.contains_key("--commit") {
        if text("--commit")? != "yes" {
            return Err(malformed("publication requires --commit yes"));
        }
        Some(digest(text("--approve-recipe")?)?)
    } else {
        if values.contains_key("--approve-recipe") {
            return Err(malformed("recipe approval requires explicit publication"));
        }
        None
    };
    let roots = number("--max-roots", 16384, 1, 65536)? as usize;
    let scan = number("--max-scan-roots", 65536, roots as u64, 262144)? as usize;
    let objects = number("--max-objects", 65536, 1, 131072)? as usize;
    let object_bytes = number(
        "--max-object-bytes",
        32 * 1024 * 1024,
        1024,
        32 * 1024 * 1024,
    )? as usize;
    let storage = LocalPublicationLimits::new(
        roots,
        MAX_MANIFEST_CHILDREN,
        roots,
        scan,
        SpoolLimits::new(
            objects,
            number("--max-total-bytes", 1024 * 1024 * 1024, 1, 1 << 40)?,
            object_bytes,
            objects,
        ),
    );
    storage
        .validate()
        .map_err(|_| malformed("inconsistent storage ceilings"))?;
    Ok(Options {
        root: PathBuf::from(required("--root")?),
        draft: PathBuf::from(required("--draft")?),
        draft_id: digest(text("--draft-id")?)?,
        approval,
        timeout: Duration::from_millis(number("--timeout-ms", 30000, 1, 3600000)?),
        steps: number("--max-steps", 65536, 1, 1000000)?,
        work: number("--max-work", 1_000_000_000_000, 1, 1_000_000_000_000_000)?,
        draft_bytes: number(
            "--max-draft-bytes",
            json_input::MAX_INPUT_BYTES as u64,
            1,
            json_input::MAX_INPUT_BYTES as u64,
        )? as usize,
        timings: number("--max-timings", 4096, 0, 4096)? as usize,
        windows: number("--max-windows", 1024, 1, 1024)? as usize,
        output_bytes: number(
            "--max-output-bytes",
            64 * 1024 * 1024,
            1,
            1024 * 1024 * 1024,
        )?,
        source: DatagramArchiveLimits {
            max_datagrams: number("--max-datagrams", 8192, 1, 65536)? as usize,
            max_payload_bytes: number(
                "--max-source-bytes",
                256 * 1024 * 1024,
                1,
                1024 * 1024 * 1024,
            )?,
            max_scan_roots: scan,
            max_spool_object_bytes: object_bytes,
        },
        storage,
    })
}

pub(super) struct Draft {
    pub scope: DatagramScope,
    pub pin: DatagramPin,
    pub hevc: HevcReplaySpec,
    pub recording: HevcRecordingReplaySpec,
    pub inputs: Vec<TimingInput>,
}
type Fields = BTreeMap<String, Value>;
fn fields<'a>(v: &'a Value, keys: &[&str]) -> Result<&'a Fields> {
    let m = v
        .object()
        .ok_or_else(|| malformed("expected JSON object"))?;
    if m.len() != keys.len() || keys.iter().any(|k| !m.contains_key(*k)) {
        return Err(malformed("draft has missing or unknown fields"));
    }
    Ok(m)
}
fn value<'a>(m: &'a Fields, k: &str) -> Result<&'a Value> {
    m.get(k).ok_or_else(|| malformed("missing draft field"))
}
fn text<'a>(m: &'a Fields, k: &str) -> Result<&'a str> {
    value(m, k)?
        .text()
        .ok_or_else(|| malformed("expected JSON string"))
}
fn integer(m: &Fields, k: &str, min: i128, max: i128) -> Result<i128> {
    let Value::Number(raw) = value(m, k)? else {
        return Err(malformed("expected JSON integer"));
    };
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || raw == "-0" {
        return Err(malformed("expected exact decimal integer"));
    }
    let n = raw
        .parse::<i128>()
        .map_err(|_| malformed("integer overflow"))?;
    if !(min..=max).contains(&n) {
        return Err(malformed("draft integer out of range"));
    }
    Ok(n)
}
fn hex(raw: &str) -> Result<Vec<u8>> {
    if raw.is_empty() || raw.len() > 65536 || !raw.len().is_multiple_of(2) {
        return Err(malformed("parameter hex must contain 1..32768 bytes"));
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = Vec::new();
    out.try_reserve_exact(raw.len() / 2)
        .map_err(|_| runtime("parameter allocation refused"))?;
    for pair in raw.as_bytes().as_chunks::<2>().0 {
        let a = digit(pair[0]).ok_or_else(|| malformed("expected lowercase parameter hex"))?;
        let b = digit(pair[1]).ok_or_else(|| malformed("expected lowercase parameter hex"))?;
        out.push((a << 4) | b);
    }
    Ok(out)
}
pub(super) fn draft(bytes: &[u8], o: &Options) -> Result<Draft> {
    let parsed = json_input::parse(
        std::str::from_utf8(bytes).map_err(|_| malformed("draft must be UTF-8"))?,
    )
    .map_err(|_| malformed("draft JSON or parser bounds refused"))?;
    let all = fields(&parsed, &["schema", "source", "recording", "timings"])?;
    if text(all, "schema")? != "fss.hevc_recipe_draft.v1" {
        return Err(malformed("unsupported draft schema"));
    }
    let s = fields(
        value(all, "source")?,
        &[
            "ingress",
            "generation",
            "ssrc",
            "peer",
            "authority",
            "rtp_channel",
            "rtcp_channel",
            "receive_clock",
            "retention_evidence",
            "head",
            "datagrams",
            "payload_bytes",
        ],
    )?;
    let ingress = text(s, "ingress")?;
    if ingress.is_empty()
        || ingress.starts_with('0')
        || !ingress.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(malformed(
            "ingress must be nonzero canonical decimal string",
        ));
    }
    let key = StreamKey {
        ingress: ingress
            .parse::<u128>()
            .map_err(|_| malformed("source ingress overflow"))?,
        generation: integer(s, "generation", 1, u64::MAX as i128)? as u64,
        ssrc: integer(s, "ssrc", 0, u32::MAX as i128)? as u32,
    };
    let scope = DatagramScope {
        binding: fss_reference::rtsp::tcp::TcpBinding::new(
            key,
            text(s, "peer")?
                .parse()
                .map_err(|_| malformed("expected original literal peer"))?,
            text(s, "authority")?,
            fss_reference::rtsp::tcp::TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
        .map_err(|_| malformed("invalid source binding"))?,
        channels: (
            integer(s, "rtp_channel", 0, 255)? as u8,
            integer(s, "rtcp_channel", 0, 255)? as u8,
        ),
        receive_clock: digest(text(s, "receive_clock")?)?,
        retention_evidence: digest(text(s, "retention_evidence")?)?,
    };
    let pin = DatagramPin {
        scope: scope
            .digest()
            .map_err(|_| malformed("invalid source scope"))?,
        head: digest(text(s, "head")?)?,
        datagrams: integer(s, "datagrams", 0, o.source.max_datagrams as i128)? as u64,
        payload_bytes: integer(s, "payload_bytes", 0, o.source.max_payload_bytes as i128)? as u64,
    };
    let r = fields(
        value(all, "recording")?,
        &[
            "sensor",
            "stream",
            "anchor",
            "time_scale",
            "timing_evidence",
            "configuration_evidence",
            "payload_type",
            "reduced_rtcp",
            "sprop_max_don_diff",
            "vps_hex",
            "sps_hex",
            "pps_hex",
        ],
    )?;
    let hevc = HevcReplaySpec {
        payload_type: integer(r, "payload_type", 0, 127)? as u8,
        // Nonzero DON requires a separately implemented interpretation, never implicit downgrade.
        sprop_max_don_diff: integer(r, "sprop_max_don_diff", 0, 0)? as u16,
        reduced_rtcp: value(r, "reduced_rtcp")?
            .boolean()
            .ok_or_else(|| malformed("expected RTCP policy boolean"))?,
        configuration_evidence: digest(text(r, "configuration_evidence")?)?,
        reorder: ReorderLimits::default(),
        reconstruction: H265Limits::default(),
    };
    let recording = HevcRecordingReplaySpec {
        scope: RecordingScope {
            sensor: SensorId::parse(text(r, "sensor")?)
                .map_err(|_| malformed("invalid sensor identity"))?,
            stream: StreamId::parse(text(r, "stream")?)
                .map_err(|_| malformed("invalid stream identity"))?,
            generation: key.generation,
            anchor: digest(text(r, "anchor")?)?,
            receive_clock: scope.receive_clock,
        },
        configuration: HevcConfiguration::parse(
            &hex(text(r, "vps_hex")?)?,
            &hex(text(r, "sps_hex")?)?,
            &hex(text(r, "pps_hex")?)?,
            HevcConfigurationLimits::default(),
        )
        .map_err(|_| malformed("original HEVC parameter sets refused"))?,
        time_scale: integer(r, "time_scale", 1, u32::MAX as i128)? as u32,
        timing_evidence: digest(text(r, "timing_evidence")?)?,
        limits: CollectorLimits::default(),
        assembly: HevcAssemblyLimits::default(),
    };
    let rows = value(all, "timings")?
        .array()
        .ok_or_else(|| malformed("timings must be an array"))?;
    if rows.len() > o.timings {
        return Err(malformed("timing row bound exceeded"));
    }
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(rows.len())
        .map_err(|_| runtime("timing allocation refused"))?;
    for row in rows {
        let t = fields(
            row,
            &[
                "rtp_timestamp",
                "decode_time",
                "duration",
                "composition_offset",
            ],
        )?;
        inputs.push(TimingInput {
            rtp_timestamp: integer(t, "rtp_timestamp", 0, u32::MAX as i128)? as u32,
            timing: HevcRecordingTiming {
                decode_time: integer(t, "decode_time", 0, u64::MAX as i128)? as u64,
                duration: integer(t, "duration", 1, u32::MAX as i128)? as u32,
                composition_offset: integer(
                    t,
                    "composition_offset",
                    i32::MIN as i128,
                    i32::MAX as i128,
                )? as i32,
            },
        });
    }
    Ok(Draft {
        scope,
        pin,
        hevc,
        recording,
        inputs,
    })
}
