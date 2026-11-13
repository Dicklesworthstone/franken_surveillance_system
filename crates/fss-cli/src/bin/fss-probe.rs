//! `fss-probe` — name the container family of a head without decoding it (FSS-053).
//!
//! Reads at most `--bytes` (default 32) from stdin and prints one stable line. Exit status is the
//! contract: 0 identified, 10 insufficient, 11 unsupported, 12 contradictory, 2 usage/IO.

use std::io::{Read, Write};

use fss_container::probe::{ProbeLimits, ProbeOutcome, probe};

const EXIT_OK: i32 = 0;
const EXIT_INSUFFICIENT: i32 = 10;
const EXIT_UNSUPPORTED: i32 = 11;
const EXIT_CONTRADICTORY: i32 = 12;
const EXIT_USAGE: i32 = 2;

fn main() {
    let mut out = std::io::stdout();
    let code = run(std::env::args().skip(1), &mut std::io::stdin(), &mut out);
    let _ = out.flush();
    std::process::exit(code);
}

/// Runs one probe, writing the report to `out` and returning the exit status.
fn run<I, R, W>(args: I, input: &mut R, out: &mut W) -> i32
where
    I: IntoIterator<Item = String>,
    R: Read,
    W: Write,
{
    let mut want = 32usize;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bytes" => match args.next().and_then(|v| v.parse::<usize>().ok()) {
                Some(value) => want = value,
                None => {
                    let _ = writeln!(out, "error: --bytes needs a count");
                    return EXIT_USAGE;
                }
            },
            "--help" | "-h" => {
                let _ = writeln!(out, "usage: fss-probe [--bytes N] < header");
                return EXIT_OK;
            }
            other => {
                let _ = writeln!(out, "error: unknown argument {other}");
                return EXIT_USAGE;
            }
        }
    }
    let limits = ProbeLimits::new(want);
    let mut head = vec![0u8; limits.max_bytes];
    // A pipe hands back short reads freely, so fill the window before deciding; a single `read`
    // would report Insufficient on a head that is actually complete.
    let mut read = 0usize;
    while read < head.len() {
        match input.read(&mut head[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) => {
                let _ = writeln!(out, "error: stdin: {error}");
                return EXIT_USAGE;
            }
        }
    }
    match probe(&head[..read], &limits) {
        ProbeOutcome::Identified {
            container,
            media,
            brand,
        } => {
            if let Some(brand) = brand {
                let _ = writeln!(
                    out,
                    "identified container={} media={} brand={}",
                    container.as_str(),
                    media.as_str(),
                    String::from_utf8_lossy(brand)
                );
            } else {
                let _ = writeln!(
                    out,
                    "identified container={} media={} bytes={read}",
                    container.as_str(),
                    media.as_str()
                );
            }
            EXIT_OK
        }
        ProbeOutcome::Insufficient { needed } => {
            let _ = writeln!(out, "insufficient needed={needed} have={read}");
            EXIT_INSUFFICIENT
        }
        ProbeOutcome::Unsupported => {
            let _ = writeln!(out, "unsupported bytes={read}");
            EXIT_UNSUPPORTED
        }
        ProbeOutcome::Contradictory => {
            let _ = writeln!(out, "contradictory bytes={read}");
            EXIT_CONTRADICTORY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exit status is the contract, so every arm is driven through `run`.
    fn invoke(args: &[&str], head: &[u8]) -> (i32, String) {
        let mut input = head;
        let mut out = Vec::new();
        let code = run(
            args.iter().map(|a| (*a).to_owned()),
            &mut input,
            &mut out,
        );
        (code, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn isobmff_reports_brand_and_exits_zero() {
        let (code, line) = invoke(&[], b"\x00\x00\x00\x18ftypisomxxxx");
        assert_eq!(code, EXIT_OK);
        assert_eq!(line.trim(), "identified container=iso-bmff media=video brand=isom");
    }

    #[test]
    fn short_head_exits_insufficient() {
        let (code, line) = invoke(&[], b"FLV");
        assert_eq!(code, EXIT_INSUFFICIENT);
        assert!(line.contains("needed=12"), "{line}");
    }

    #[test]
    fn unknown_head_exits_unsupported() {
        let (code, _) = invoke(&[], b"RIFFxxxxWAVE");
        assert_eq!(code, EXIT_UNSUPPORTED);
    }

    #[test]
    fn budget_below_the_longest_prefix_is_insufficient() {
        let (code, _) = invoke(&["--bytes", "4"], b"\x00\x00\x00\x18ftypisom");
        assert_eq!(code, EXIT_INSUFFICIENT);
    }

    #[test]
    fn jpeg_maps_to_image() {
        let (code, line) = invoke(&[], &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(code, EXIT_OK);
        assert!(line.contains("media=image"), "{line}");
    }

    #[test]
    fn a_short_reading_pipe_still_identifies() {
        /// Yields one byte per call, like a pipe that is being filled slowly.
        struct Dribble(&'static [u8], usize);
        impl Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
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
        let mut input = Dribble(b"\x1a\x45\xdf\xa3matroska", 0);
        let mut out = Vec::new();
        let code = run(std::iter::empty(), &mut input, &mut out);
        assert_eq!(code, EXIT_OK);
        assert!(String::from_utf8_lossy(&out).contains("matroska"));
    }

    #[test]
    fn bad_argument_exits_usage() {
        assert_eq!(invoke(&["--bytes"], b"").0, EXIT_USAGE);
        assert_eq!(invoke(&["--wat"], b"").0, EXIT_USAGE);
    }

    #[test]
    fn help_exits_zero() {
        let (code, line) = invoke(&["--help"], b"");
        assert_eq!(code, EXIT_OK);
        assert!(line.starts_with("usage:"), "{line}");
    }
}
