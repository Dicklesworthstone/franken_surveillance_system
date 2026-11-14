#![forbid(unsafe_code)]
//! fss-probe: bounded container-family, Annex-B or MP4 initialization inspection.
//!
//! Reads at most --bytes from stdin. The default is 189 bytes for signatures,
//! or 4096 for --parameters. No decoding, networking or source retention occurs.
//! Exit status: 0 identified, 10 insufficient, 11 unsupported, 12 contradictory,
//! 13 malformed parameters, 14 limited, 15 cancelled, 2 usage/IO/allocation.

use std::io::{self, Read, Write};

use fss_container::probe::{
    MAX_PROBE_BYTES, ProbeLimits, ProbeOutcome, TRANSPORT_PREFIX,
    parameters::{ParameterError, ParameterLimits, probe_parameters},
    probe,
};

const EXIT_OK: i32 = 0;
const EXIT_INSUFFICIENT: i32 = 10;
const EXIT_UNSUPPORTED: i32 = 11;
const EXIT_CONTRADICTORY: i32 = 12;
const EXIT_MALFORMED: i32 = 13;
const EXIT_LIMIT: i32 = 14;
const EXIT_CANCELLED: i32 = 15;
const EXIT_USAGE: i32 = 2;

fn main() {
    let mut out = std::io::stdout();
    let code = run(std::env::args().skip(1), &mut std::io::stdin(), &mut out);
    let code = if out.flush().is_ok() {
        code
    } else {
        EXIT_USAGE
    };
    std::process::exit(code);
}

/// Runs one probe. A failed output write never reports successful inspection.
fn run<I, R, W>(args: I, input: &mut R, out: &mut W) -> i32
where
    I: IntoIterator<Item = String>,
    R: Read,
    W: Write,
{
    run_inner(args, input, out).unwrap_or(EXIT_USAGE)
}

fn run_inner<I, R, W>(args: I, input: &mut R, out: &mut W) -> io::Result<i32>
where
    I: IntoIterator<Item = String>,
    R: Read,
    W: Write,
{
    let mut want = None;
    let mut units = None;
    let mut parameters = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bytes" if want.is_none() => {
                match args.next().and_then(|value| value.parse::<usize>().ok()) {
                    Some(value) if (1..=MAX_PROBE_BYTES).contains(&value) => {
                        want = Some(value);
                    }
                    _ => {
                        writeln!(out, "error: --bytes needs a count in 1..=4096")?;
                        return Ok(EXIT_USAGE);
                    }
                }
            }
            "--units" if units.is_none() => {
                match args.next().and_then(|value| value.parse::<usize>().ok()) {
                    Some(value) if (1..=64).contains(&value) => units = Some(value),
                    _ => {
                        writeln!(out, "error: --units needs a count in 1..=64")?;
                        return Ok(EXIT_USAGE);
                    }
                }
            }
            "--parameters" if !parameters => parameters = true,
            "--help" | "-h" => {
                writeln!(
                    out,
                    "usage: fss-probe [--bytes N] [--parameters [--units N]] < header"
                )?;
                return Ok(EXIT_OK);
            }
            _ => {
                writeln!(out, "error: unknown or repeated argument")?;
                return Ok(EXIT_USAGE);
            }
        }
    }
    if units.is_some() && !parameters {
        writeln!(out, "error: --units requires --parameters")?;
        return Ok(EXIT_USAGE);
    }
    let max_bytes = want.unwrap_or(if parameters {
        MAX_PROBE_BYTES
    } else {
        TRANSPORT_PREFIX
    });
    let parameter_limits = ParameterLimits {
        max_bytes,
        max_units: units.unwrap_or(64),
        ..ParameterLimits::default()
    };
    if parameters && parameter_limits.validate().is_err() {
        writeln!(out, "error: parameter probing needs --bytes in 12..=4096")?;
        return Ok(EXIT_USAGE);
    }

    let mut head = [0u8; MAX_PROBE_BYTES];
    let mut read = 0usize;
    let mut end_of_source = false;
    let mut interrupted = 0usize;
    // Short reads are normal for pipes. Filling the allowance does not prove EOF,
    // and no extra lookahead byte is read merely to decide whether EOF occurred.
    while read < max_bytes {
        match input.read(&mut head[read..max_bytes]) {
            Ok(0) => {
                end_of_source = true;
                break;
            }
            Ok(count) if count <= max_bytes - read => read += count,
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 64 => {
                interrupted += 1;
            }
            Err(error) => return Err(error),
        }
    }

    if parameters {
        return match probe_parameters(&head[..read], end_of_source, parameter_limits, || false) {
            Ok(report) => {
                write!(
                    out,
                    "parameters container={} codec={} scope=configuration-prefix \
                     coded_width={} coded_height={} display_width={} display_height={} \
                     bit_depth={} profile={} level={} vps=",
                    report.container.as_str(),
                    report.codec.as_str(),
                    report.coded_dimensions.0,
                    report.coded_dimensions.1,
                    report.display_dimensions.0,
                    report.display_dimensions.1,
                    report.bit_depth,
                    report.profile,
                    report.level,
                )?;
                if let Some(vps) = &report.vps {
                    write!(out, "{}..{}", vps.range.start, vps.range.end)?;
                } else {
                    write!(out, "none")?;
                }
                write!(
                    out,
                    " sps={}..{} pps={}..{} inspected_bytes={} inspected_units={}",
                    report.sps.range.start,
                    report.sps.range.end,
                    report.pps.range.start,
                    report.pps.range.end,
                    report.inspected_bytes,
                    report.inspected_units,
                )?;
                if let Some(track) = report.track_id {
                    write!(out, " track_id={track}")?;
                }
                writeln!(out, " bytes={read}")?;
                Ok(EXIT_OK)
            }
            Err(error) => {
                let (status, exit) = match error {
                    ParameterError::Truncated => ("insufficient", EXIT_INSUFFICIENT),
                    ParameterError::Unsupported => ("unsupported", EXIT_UNSUPPORTED),
                    ParameterError::Contradictory => ("contradictory", EXIT_CONTRADICTORY),
                    ParameterError::Malformed => ("malformed", EXIT_MALFORMED),
                    ParameterError::Limit => ("limited", EXIT_LIMIT),
                    ParameterError::Cancelled => ("cancelled", EXIT_CANCELLED),
                    ParameterError::Configuration | ParameterError::Allocation => {
                        ("error", EXIT_USAGE)
                    }
                };
                writeln!(out, "{status} parameters reason={error:?} bytes={read}")?;
                Ok(exit)
            }
        };
    }

    match probe(&head[..read], &ProbeLimits { max_bytes }) {
        ProbeOutcome::Identified {
            container,
            media,
            brand,
        } => {
            write!(
                out,
                "identified container={} media={}",
                container.as_str(),
                media.as_str()
            )?;
            if let Some(brand) = brand {
                write!(out, " brand=")?;
                // Major brands are untrusted source bytes. Keep one output line
                // and one field even for control characters, spaces or invalid UTF-8.
                for byte in brand {
                    if byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-') {
                        write!(out, "{}", char::from(*byte))?;
                    } else {
                        write!(out, "%{byte:02X}")?;
                    }
                }
                writeln!(out)?;
            } else {
                writeln!(out, " bytes={read}")?;
            }
            Ok(EXIT_OK)
        }
        ProbeOutcome::Insufficient { needed } => {
            writeln!(out, "insufficient needed={needed} have={read}")?;
            Ok(EXIT_INSUFFICIENT)
        }
        ProbeOutcome::Unsupported => {
            writeln!(out, "unsupported bytes={read}")?;
            Ok(EXIT_UNSUPPORTED)
        }
        ProbeOutcome::Contradictory => {
            writeln!(out, "contradictory bytes={read}")?;
            Ok(EXIT_CONTRADICTORY)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVC: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-packet/tests/fixtures/avc/baseline.264"
    ));

    fn invoke(args: &[&str], head: &[u8]) -> (i32, String) {
        let mut input = head;
        let mut out = Vec::new();
        let code = run(
            args.iter().map(|arg| (*arg).to_owned()),
            &mut input,
            &mut out,
        );
        (code, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn isobmff_reports_brand_and_exits_zero() {
        let (code, line) = invoke(&[], b"\x00\x00\x00\x18ftypisomxxxx");
        assert_eq!(code, EXIT_OK);
        assert_eq!(
            line.trim(),
            "identified container=iso-bmff media=video brand=isom"
        );
    }

    #[test]
    fn short_head_exits_insufficient() {
        let (code, line) = invoke(&[], b"FLV");
        assert_eq!(code, EXIT_INSUFFICIENT);
        assert!(line.contains("needed=12"), "{line}");
    }

    #[test]
    fn unknown_head_exits_unsupported() {
        assert_eq!(invoke(&[], b"RIFFxxxxWAVE").0, EXIT_UNSUPPORTED);
    }

    #[test]
    fn budget_below_the_minimum_prefix_is_insufficient() {
        assert_eq!(
            invoke(&["--bytes", "4"], b"\x00\x00\x00\x18ftypisom").0,
            EXIT_INSUFFICIENT
        );
    }

    #[test]
    fn jpeg_maps_to_image() {
        let (code, line) = invoke(&[], &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(code, EXIT_OK);
        assert!(line.contains("media=image"), "{line}");
    }

    #[test]
    fn short_reads_and_interruption_do_not_change_identification() {
        struct Dribble(&'static [u8], usize, bool);
        impl Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.2 {
                    self.2 = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let Some(byte) = self.0.get(self.1) else {
                    return Ok(0);
                };
                if buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = *byte;
                self.1 += 1;
                Ok(1)
            }
        }
        let mut input = Dribble(b"\x1a\x45\xdf\xa3matroska", 0, false);
        let mut out = Vec::new();
        assert_eq!(run(std::iter::empty(), &mut input, &mut out), EXIT_OK);
        assert!(String::from_utf8_lossy(&out).contains("matroska"));
    }

    #[test]
    fn bad_arguments_fail_without_silently_widening_or_clamping() {
        for args in [
            &["--bytes"][..],
            &["--wat"][..],
            &["--bytes", "0"][..],
            &["--bytes", "4097"][..],
            &["--units", "2"][..],
            &["--parameters", "--units", "65"][..],
            &["--parameters", "--bytes", "4"][..],
            &["--bytes", "32", "--bytes", "64"][..],
        ] {
            assert_eq!(invoke(args, b"").0, EXIT_USAGE);
        }
    }

    #[test]
    fn help_exits_zero() {
        let (code, line) = invoke(&["--help"], b"");
        assert_eq!(code, EXIT_OK);
        assert!(line.starts_with("usage:"), "{line}");
    }

    #[test]
    fn default_budget_identifies_transport_and_short_budget_requests_more() {
        let mut bytes = vec![0; 376];
        bytes[0] = 0x47;
        bytes[188] = 0x47;
        let (code, line) = invoke(&[], &bytes);
        assert_eq!(code, EXIT_OK);
        assert!(line.contains("container=mpeg-ts"), "{line}");
        assert_eq!(
            invoke(&["--bytes", "32"], &bytes),
            (
                EXIT_INSUFFICIENT,
                "insufficient needed=189 have=32\n".into()
            )
        );
        let mut input = &bytes[..];
        let mut out = Vec::new();
        assert_eq!(run(std::iter::empty(), &mut input, &mut out), EXIT_OK);
        assert_eq!(input.len(), bytes.len() - TRANSPORT_PREFIX);
    }

    #[test]
    fn parameters_report_native_metadata_and_refuse_exhausted_work() {
        let (code, line) = invoke(&["--parameters"], AVC);
        assert_eq!(code, EXIT_OK, "{line}");
        assert!(
            line.contains("codec=h264 scope=configuration-prefix"),
            "{line}"
        );
        assert!(line.contains("coded_width=160 coded_height=128"), "{line}");
        assert!(line.contains("bit_depth=8 profile=66 level=11"), "{line}");
        assert!(line.contains("vps=none sps="), "{line}");
        assert_eq!(invoke(&["--parameters", "--units", "1"], AVC).0, EXIT_LIMIT);
        assert_eq!(
            invoke(&["--parameters"], b"\x00\x00\x00\x18ftypisom").0,
            EXIT_INSUFFICIENT
        );
    }

    #[test]
    fn mp4_parameters_report_actual_container_track_and_prefix_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = include_bytes!("../../../fss-container/tests/fixtures/fragmented_av.mp4");
        let (code, line) = invoke(&["--parameters"], bytes);
        assert_eq!(code, EXIT_OK, "{line}");
        assert!(
            line.starts_with("parameters container=iso-bmff codec=h264 "),
            "{line}"
        );
        assert!(line.contains("track_id=1"), "{line}");
        assert!(line.contains("inspected_bytes=1214"), "{line}");
        assert!(line.contains("coded_width=64 coded_height=48"), "{line}");
        assert_eq!(
            invoke(&["--parameters", "--bytes", "1214"], bytes).0,
            EXIT_OK
        );
        assert_eq!(
            invoke(&["--parameters", "--bytes", "1213"], bytes).0,
            EXIT_LIMIT
        );
        assert_eq!(
            invoke(&["--parameters"], &bytes[..1213]).0,
            EXIT_INSUFFICIENT
        );
        assert_eq!(
            invoke(&["--parameters", "--units", "1"], bytes).0,
            EXIT_LIMIT
        );
        let hevc = include_bytes!("../../../fss-container/tests/fixtures/hevc_fragmented_av.mp4");
        let (code, line) = invoke(&["--parameters"], hevc);
        assert_eq!(code, EXIT_OK, "{line}");
        assert!(
            line.starts_with("parameters container=iso-bmff codec=h265 "),
            "{line}"
        );
        assert!(line.contains("bit_depth=8 profile=1 level=30"), "{line}");
        Ok(())
    }

    #[test]
    fn mp4_parameters_do_not_seek_to_late_metadata_or_accept_inband_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let late = include_bytes!("../../../fss-container/tests/fixtures/hevc_av.mp4");
        assert_eq!(invoke(&["--parameters"], late).0, EXIT_LIMIT);
        let mut bytes =
            include_bytes!("../../../fss-container/tests/fixtures/baseline_init.bin").to_vec();
        // A compatible brand may also name avc1; the final occurrence is this fixture's entry.
        let at = bytes
            .windows(4)
            .rposition(|kind| kind == b"avc1")
            .ok_or("fixture avc1 entry")?;
        bytes[at..at + 4].copy_from_slice(b"avc3");
        assert_eq!(invoke(&["--parameters"], &bytes).0, EXIT_UNSUPPORTED);
        Ok(())
    }

    #[test]
    fn a_full_read_allowance_cannot_close_an_undelimited_parameter_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = probe_parameters(AVC, false, ParameterLimits::default(), || false)?;
        let source = &AVC[..report.pps.range.end];
        let exact = source.len().to_string();
        let with_eof = (source.len() + 1).to_string();
        assert_eq!(
            invoke(&["--parameters", "--bytes", &exact], source).0,
            EXIT_LIMIT
        );
        assert_eq!(
            invoke(&["--parameters", "--bytes", &with_eof], source).0,
            EXIT_OK
        );
        Ok(())
    }

    #[test]
    fn hostile_brand_is_one_escaped_field_on_one_line() {
        let (code, line) = invoke(&[], b"\x00\x00\x00\x18ftypa\n=b");
        assert_eq!(code, EXIT_OK);
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("brand=a%0A%3Db"), "{line}");
    }

    #[test]
    fn output_errors_and_persistent_interruptions_are_not_success() {
        struct FailedOutput;
        impl Write for FailedOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut input = &b"\x00\x00\x00\x18ftypisom"[..];
        assert_eq!(
            run(std::iter::empty(), &mut input, &mut FailedOutput),
            EXIT_USAGE
        );
        struct Interrupted(usize);
        impl Read for Interrupted {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::ErrorKind::Interrupted.into())
            }
        }
        let mut input = Interrupted(0);
        assert_eq!(
            run(std::iter::empty(), &mut input, &mut Vec::new()),
            EXIT_USAGE
        );
        assert_eq!(input.0, 65);
    }
}
