//! `fss-probe` — name the container family of a head without decoding it (FSS-053).
//!
//! Reads at most `--bytes` (default 32) from stdin and prints one stable line. Exit status is the
//! contract: 0 identified, 10 insufficient, 11 unsupported, 12 contradictory, 2 usage/IO.

use std::io::Read;

use fss_container::probe::{MAX_PREFIX, ProbeLimits, ProbeOutcome, probe};

const EXIT_INSUFFICIENT: i32 = 10;
const EXIT_UNSUPPORTED: i32 = 11;
const EXIT_CONTRADICTORY: i32 = 12;
const EXIT_USAGE: i32 = 2;

fn main() {
    let mut want = 32usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bytes" => match args.next().and_then(|v| v.parse::<usize>().ok()) {
                Some(value) => want = value,
                None => {
                    eprintln!("--bytes needs a count");
                    std::process::exit(EXIT_USAGE);
                }
            },
            "--help" | "-h" => {
                println!("usage: fss-probe [--bytes N] < header");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(EXIT_USAGE);
            }
        }
    }
    let limits = ProbeLimits::new(want);
    let mut head = vec![0u8; limits.max_bytes];
    let read = match std::io::stdin().read(&mut head) {
        Ok(read) => read,
        Err(error) => {
            eprintln!("stdin: {error}");
            std::process::exit(EXIT_USAGE);
        }
    };
    match probe(&head[..read], &limits) {
        ProbeOutcome::Identified {
            container,
            media,
            brand,
        } => {
            match brand {
                Some(brand) => println!(
                    "identified container={} media={} brand={}",
                    container.as_str(),
                    media.as_str(),
                    String::from_utf8_lossy(brand)
                ),
                None => println!(
                    "identified container={} media={} bytes={read}",
                    container.as_str(),
                    media.as_str()
                ),
            }
        }
        ProbeOutcome::Insufficient { needed } => {
            println!("insufficient needed={needed} have={read}");
            std::process::exit(EXIT_INSUFFICIENT);
        }
        ProbeOutcome::Unsupported => {
            println!("unsupported bytes={read}");
            std::process::exit(EXIT_UNSUPPORTED);
        }
        ProbeOutcome::Contradictory => {
            println!("contradictory bytes={read}");
            std::process::exit(EXIT_CONTRADICTORY);
        }
    }
    debug_assert!(MAX_PREFIX <= 32);
}
