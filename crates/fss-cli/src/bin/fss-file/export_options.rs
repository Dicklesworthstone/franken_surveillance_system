#![forbid(unsafe_code)]
//! Shared, explicit options for bounded private decoded-media output.

use super::super::{ParseResult, Values, malformed, number, text};
use super::{OutputFormat, jpeg_stream, pgm_stream};
use fss_container::matroska_gray::PlaybackRate;
use std::path::PathBuf;

#[derive(Debug)]
pub(super) struct ExportOptions {
    pub(super) output: Option<PathBuf>,
    pub(super) maximum_output_bytes: Option<u64>,
    pub(super) output_format: OutputFormat,
    pub(super) output_rate: Option<PlaybackRate>,
    pub(super) jpeg_quality: u8,
    pub(super) encode_work_units: u64,
}

impl ExportOptions {
    pub(super) fn parse(values: &Values) -> ParseResult<Self> {
        let output_format = if values.contains_key("--output-format") {
            if !values.contains_key("--output") {
                return Err(malformed("--output-format requires --output"));
            }
            match text(values, "--output-format")? {
                "pgm" => OutputFormat::Pgm,
                "mjpeg" => OutputFormat::Mjpeg,
                "gray-mkv" => OutputFormat::GrayMatroska,
                _ => return Err(malformed("output format must be pgm, mjpeg or gray-mkv")),
            }
        } else {
            OutputFormat::Pgm
        };
        let output_rate = if output_format == OutputFormat::GrayMatroska {
            let value = text(values, "--output-rate")?;
            if value.len() > 15 {
                return Err(malformed(
                    "output rate requires NUM/DEN with components in 1..1000000",
                ));
            }
            let (numerator, denominator) = value
                .split_once('/')
                .ok_or_else(|| malformed("output rate requires NUM/DEN"))?;
            let integer = |part: &str| {
                if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(malformed(
                        "output rate requires positive decimal components",
                    ));
                }
                part.parse::<u32>()
                    .map_err(|_| malformed("output rate component exceeds limit"))
            };
            Some(
                PlaybackRate::new(integer(numerator)?, integer(denominator)?)
                    .map_err(|_| malformed("output rate components must be in 1..1000000"))?,
            )
        } else {
            if values.contains_key("--output-rate") {
                return Err(malformed("--output-rate requires --output-format gray-mkv"));
            }
            None
        };
        if output_format != OutputFormat::Mjpeg
            && (values.contains_key("--jpeg-quality") || values.contains_key("--encode-work-units"))
        {
            return Err(malformed(
                "JPEG quality and encode work require --output-format mjpeg",
            ));
        }
        let jpeg_quality: u8 =
            number(values, "--jpeg-quality", Some(jpeg_stream::DEFAULT_QUALITY))?;
        if !(1..=100).contains(&jpeg_quality) {
            return Err(malformed("JPEG quality must be 1..100"));
        }
        let encode_work_units = number(
            values,
            "--encode-work-units",
            Some(jpeg_stream::DEFAULT_ENCODE_WORK_UNITS),
        )?;
        let maximum_output_bytes = if values.contains_key("--max-output-bytes") {
            let maximum: u64 = number(values, "--max-output-bytes", None)?;
            if !values.contains_key("--output")
                || maximum == 0
                || maximum > pgm_stream::MAX_OUTPUT_BYTES
            {
                return Err(malformed(
                    "--max-output-bytes requires --output and a value in 1..268435456",
                ));
            }
            Some(maximum)
        } else {
            None
        };
        Ok(Self {
            output: values.get("--output").map(PathBuf::from),
            maximum_output_bytes,
            output_format,
            output_rate,
            jpeg_quality,
            encode_work_units,
        })
    }
}
