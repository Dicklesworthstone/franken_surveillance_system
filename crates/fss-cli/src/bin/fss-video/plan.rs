#![forbid(unsafe_code)]
//! Pure operator-selected scope. No storage, clock, codec or network access during planning.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, PrincipalId};
use fss_reference::ingest::RetainedReadLimits;

use crate::{Result, fail};

pub(crate) const MAX_ARGUMENTS: usize = 65;
pub(crate) const REPORT_LIMIT: usize = 4 * 1024 * 1024;
pub(crate) const SCHEMA: &str = "fss.native_video_cli.v1";
const POLICY: &str = "explicit-codec-import-and-privacy:sealed-native-frames:bounded-display-order:source-verified-cold-read:whole-range-replay:no-camera:no-effects:incremental-publication:v1";
pub(crate) const HELP: &str = "fss-video <publish|read|verify> [options]\n\
  --root EXISTING_ABSOLUTE_DEPLOYMENT --site SITE --import-id sha256:HEX\n\
  --codec avc|hevc --privacy-policy none|sha256:HEX --read-originals yes\n\
  publish: --first-segment N --segment-count N --retain-derived yes\n\
  read/verify: --frame-root sha256:HEX\n\
  read export (Linux): --output NEW_ABSOLUTE_FILE --pixel-format pgm|i420|rgb\n\
  [--approve sha256:HEX] [--principal principal:local-operator]\n\
  Native bounds: --max-pixels 4194304 --max-dimension 4096 --max-slices 4096\n\
  --max-segments 1024 --work-units 8000000000 --timeout-ms 30000\n\
  --max-source-bytes N --chunk-bytes N --max-segment-bytes N\n\
  Publication allowance: --max-derived-bytes 67108864 (maximum 268435456)\n\
Without --approve every command is a pure JSON preview. Repeat exactly with its approval.\n\
Publish decodes an IDR/IRAP-led range in display order and retains masked I420 plus original\n\
native receipts. Each frame commits separately; failures preserve the completed prefix.\n\
The derived allowance charges pixels, receipt and a conservative 4096-byte manifest reserve\n\
for EVERY admitted frame, including exact retries. Decoder work never refills within a call.\n\
Read verifies completed frame, whole source custody and the exact current privacy policy\n\
without decoding. Verify additionally replays the ENTIRE original range, never stopping\n\
after the selected frame. It compares receipt, source/output positions and all three planes.\n\
No new deployment, camera traffic, unmasked export, event/alert or absence authority is created.\n\
Read/verify do not append cognition. Native deployment open may perform its existing recovery.\n\
Export writes only a new file outside the deployment; a failed export may leave a partial file.\n\
PGM is luma, I420 is packed Y/Cb/Cr, RGB is packed native RGB with mask fill preserved.\n\
Timeout checks are cooperative between bounded operations, not syscall/codec preemption.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Command { Publish, Read, Verify }
impl Command {
    pub(crate) fn text(self) -> &'static str {
        match self { Self::Publish => "publish", Self::Read => "read", Self::Verify => "verify" }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Codec { Avc, Hevc }
impl Codec {
    pub(crate) fn text(self) -> &'static str {
        match self { Self::Avc => "avc", Self::Hevc => "hevc" }
    }
}
#[derive(Debug)]
pub(crate) struct Plan {
    pub command: Command,
    pub root: PathBuf,
    pub site: String,
    pub principal: String,
    pub identity: ContentDigest,
    pub codec: Codec,
    pub privacy: Option<ContentDigest>,
    pub first: usize,
    pub count: usize,
    pub frame: Option<ContentDigest>,
    pub source: RetainedReadLimits,
    pub pixels: usize,
    pub dimension: u32,
    pub slices: u32,
    pub segments: usize,
    pub work: u64,
    pub derived: usize,
    pub timeout_ms: u64,
    pub output: Option<PathBuf>,
    pub pixel_format: Option<String>,
    pub approval: Option<ContentDigest>,
}

fn digest(raw: &str) -> Result<ContentDigest> {
    let value = ContentDigest::parse(raw)?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(fail("nonzero SHA-256 required"));
    }
    Ok(value)
}
fn path(raw: &str) -> Result<PathBuf> {
    let p = PathBuf::from(raw);
    if !p.is_absolute() || p.parent().is_none() || p.file_name().is_none()
        || raw.chars().any(char::is_control)
        || raw.split('/').any(|s| matches!(s, "." | ".."))
        || p.components().any(|c| matches!(c, Component::CurDir | Component::ParentDir)) {
        return Err(fail("absolute non-root path without dot components required"));
    }
    Ok(p)
}
impl Plan {
    pub(crate) fn parse(args: &[OsString]) -> Result<Self> {
        if args.is_empty() || args.len() > MAX_ARGUMENTS || args.len().is_multiple_of(2)
            || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
            return Err(fail("bounded command and option pairs required"));
        }
        let command = match args[0].to_str() {
            Some("publish") => Command::Publish, Some("read") => Command::Read,
            Some("verify") => Command::Verify, _ => return Err(fail("unknown video command")),
        };
        let mut values = BTreeMap::new();
        for pair in args[1..].as_chunks::<2>().0 {
            let key = pair[0].to_str().ok_or_else(|| fail("UTF-8 option required"))?;
            let value = pair[1].to_str().ok_or_else(|| fail("UTF-8 value required"))?;
            let allowed = matches!(key, "--root" | "--site" | "--principal" | "--import-id"
                | "--codec" | "--privacy-policy" | "--read-originals" | "--approve"
                | "--max-source-bytes" | "--chunk-bytes" | "--max-segment-bytes"
                | "--max-pixels" | "--max-dimension" | "--timeout-ms")
                || (command != Command::Read && matches!(key, "--work-units" | "--max-slices" | "--max-segments"))
                || (command == Command::Publish && matches!(key, "--first-segment" | "--segment-count" | "--retain-derived" | "--max-derived-bytes"))
                || (command != Command::Publish && key == "--frame-root")
                || (command == Command::Read && matches!(key, "--output" | "--pixel-format"));
            if !allowed || value.is_empty() || value.starts_with("--") || values.insert(key, value).is_some() {
                return Err(fail("duplicate, unknown or inapplicable option, or missing value"));
            }
        }
        let get = |key| values.get(key).copied().ok_or_else(|| fail("required option missing"));
        let number = |key, default: u64, low: u64, high: u64| -> Result<u64> {
            let n = match values.get(key) {
                Some(raw) if raw.bytes().all(|b| b.is_ascii_digit()) => raw.parse::<u64>()?,
                Some(_) => return Err(fail("unsigned decimal required")), None => default,
            };
            if n < low || n > high { return Err(fail("numeric admission bound exceeded")); }
            Ok(n)
        };
        if get("--read-originals")? != "yes"
            || (command == Command::Publish && get("--retain-derived")? != "yes") {
            return Err(fail("explicit original-read and requested derivative-retention consent required"));
        }
        let codec = match get("--codec")? {
            "avc" => Codec::Avc, "hevc" => Codec::Hevc, _ => return Err(fail("explicit avc or hevc required")),
        };
        let privacy = match get("--privacy-policy")? { "none" => None, value => Some(digest(value)?) };
        let site = get("--site")?.to_owned();
        fss_reference::reference_deployment::validate_site_lineage(&site)?;
        let principal = values.get("--principal").copied().unwrap_or("principal:local-operator").to_owned();
        if principal.len() > 256 { return Err(fail("principal length exceeded")); }
        PrincipalId::parse(&principal)?;
        let root = path(get("--root")?)?;
        let output = values.get("--output").map(|s| path(s)).transpose()?;
        if output.as_ref().is_some_and(|p| p.starts_with(&root) || root.starts_with(p)) {
            return Err(fail("export must be outside deployment custody"));
        }
        let pixel_format = values.get("--pixel-format").map(|s| s.to_string());
        if output.is_some() != pixel_format.is_some()
            || pixel_format.as_deref().is_some_and(|s| !matches!(s, "pgm" | "i420" | "rgb")) {
            return Err(fail("output and explicit pgm, i420 or rgb format are required together"));
        }
        let segments = number("--max-segments", 1024, 1, 1024)? as usize;
        let (first, count) = if command == Command::Publish {
            get("--first-segment")?; get("--segment-count")?;
            (number("--first-segment", 0, 0, 65_535)? as usize,
             number("--segment-count", 1, 1, segments as u64)? as usize)
        } else { (0, 0) };
        if first.checked_add(count).is_none_or(|end| end > 65_536) {
            return Err(fail("native source range exceeded"));
        }
        let defaults = RetainedReadLimits::default();
        Ok(Self {
            command, root, site, principal, codec, privacy, first, count,
            identity: digest(get("--import-id")?)?,
            frame: if command == Command::Publish { None } else { Some(digest(get("--frame-root")?)?) },
            source: RetainedReadLimits {
                max_source_bytes: number("--max-source-bytes", defaults.max_source_bytes, 1, 1024 * 1024 * 1024)?,
                max_chunk_bytes: number("--chunk-bytes", defaults.max_chunk_bytes, 1, 64 * 1024 * 1024)?,
                max_segment_bytes: number("--max-segment-bytes", defaults.max_segment_bytes, 1, 64 * 1024 * 1024)?,
            },
            pixels: number("--max-pixels", 4_194_304, 1, 4_194_304)? as usize,
            dimension: number("--max-dimension", 4096, 1, 4096)? as u32,
            slices: number("--max-slices", 4096, 1, 4096)? as u32,
            segments,
            work: number("--work-units", 8_000_000_000, 0, 1_000_000_000_000)?,
            derived: number("--max-derived-bytes", 64 * 1024 * 1024, 1, 256 * 1024 * 1024)? as usize,
            timeout_ms: number("--timeout-ms", 30_000, 1, 600_000)?,
            output, pixel_format,
            approval: values.get("--approve").map(|s| digest(s)).transpose()?,
        })
    }
    pub(crate) fn digest(&self) -> Result<ContentDigest> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.native_video_cli_plan.v1"); e.text(POLICY);
        for s in [self.command.text(), self.root.to_str().ok_or_else(|| fail("UTF-8 root required"))?,
                  &self.site, &self.principal, self.codec.text()] { e.text(s); }
        e.digest(self.identity);
        for pin in [self.privacy, self.frame] { e.bool(pin.is_some()); if let Some(pin) = pin { e.digest(pin); } }
        for n in [self.first as u64, self.count as u64, self.source.max_source_bytes,
                  self.source.max_chunk_bytes, self.source.max_segment_bytes, self.pixels as u64,
                  self.dimension as u64, self.slices as u64, self.segments as u64, self.work,
                  self.derived as u64, self.timeout_ms, REPORT_LIMIT as u64] { e.u64(n); }
        e.bool(self.output.is_some());
        if let Some(output) = &self.output {
            e.text(output.to_str().ok_or_else(|| fail("UTF-8 output required"))?);
            e.text(self.pixel_format.as_deref().ok_or_else(|| fail("missing pixel format"))?);
            e.text("linux-pinned-parent:create-new:bounded-write:retain-partial-on-failure:v1");
        }
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(crate) fn preview(&self) -> Result<String> {
        Ok(object(&[
            ("schema", string(SCHEMA)), ("phase", string("planned")),
            ("command", string(self.command.text())), ("approval", string(&self.digest()?.to_text())),
            ("policy", string(POLICY)), ("root", string(self.root.to_str().ok_or_else(|| fail("root"))?)),
            ("site", string(&self.site)), ("principal", string(&self.principal)),
            ("import_identity", string(&self.identity.to_text())), ("codec", string(self.codec.text())),
            ("privacy_policy", self.privacy.map_or_else(|| "null".into(), |d| string(&d.to_text()))),
            ("frame_root", self.frame.map_or_else(|| "null".into(), |d| string(&d.to_text()))),
            ("first_segment", self.first.to_string()), ("segment_count", self.count.to_string()),
            ("maximum_segments", self.segments.to_string()), ("maximum_pixels", self.pixels.to_string()),
            ("maximum_dimension", self.dimension.to_string()), ("maximum_slices", self.slices.to_string()),
            ("maximum_source_bytes_per_pass", self.source.max_source_bytes.to_string()),
            ("maximum_chunk_bytes", self.source.max_chunk_bytes.to_string()),
            ("maximum_segment_bytes", self.source.max_segment_bytes.to_string()),
            ("maximum_decode_work_units", self.work.to_string()),
            ("decode_work_model", string(fss_reference::ingest::recorded_decode::video_budget::VIDEO_DECODE_WORK_MODEL)),
            ("maximum_derived_bytes", self.derived.to_string()), ("timeout_ms", self.timeout_ms.to_string()),
            ("maximum_report_bytes", REPORT_LIMIT.to_string()),
            ("output", match &self.output {
                Some(p) => string(p.to_str().ok_or_else(|| fail("UTF-8 output required"))?), None => "null".into(),
            }),
            ("pixel_format", self.pixel_format.as_deref().map_or_else(|| "null".into(), string)),
            ("effects", string("none-until-exact-approval")), ("network_requested", "false".into()),
            ("atomic_range_publication", "false".into()), ("absence_certifiable", "false".into()),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        ["publish", "--root", "/not-opened/deployment", "--site", "site:video", "--import-id",
         "sha256:1111111111111111111111111111111111111111111111111111111111111111",
         "--codec", "avc", "--privacy-policy", "none", "--read-originals", "yes",
         "--retain-derived", "yes", "--first-segment", "0", "--segment-count", "3"]
            .into_iter().map(OsString::from).collect()
    }
    #[test]
    fn pure_preview_binds_each_effective_limit_and_approval_does_not_change_intent() -> Result<()> {
        let base = Plan::parse(&args())?;
        let digest = base.digest()?;
        assert!(base.preview()?.contains("none-until-exact-approval"));
        for (key, value) in [("--max-pixels", "1024"), ("--max-dimension", "32"),
            ("--max-slices", "7"), ("--max-segments", "3"), ("--work-units", "0"),
            ("--max-derived-bytes", "1"), ("--timeout-ms", "1"),
            ("--max-source-bytes", "1000"), ("--chunk-bytes", "100"), ("--max-segment-bytes", "100")] {
            let mut input = args(); input.extend([key.into(), value.into()]);
            assert_ne!(Plan::parse(&input)?.digest()?, digest, "{key}");
        }
        let mut input = args(); input.extend(["--approve".into(), digest.to_text().into()]);
        assert_eq!(Plan::parse(&input)?.digest()?, digest);
        Ok(())
    }
    #[test]
    fn command_grammar_refuses_ambiguous_or_widened_intents() {
        for (key, value) in [("--codec", "hevc"), ("--frame-root", "bogus"),
            ("--work-units", "-1"), ("--max-segments", "1025"), ("--max-pixels", "4194305"),
            ("--max-derived-bytes", "268435457"), ("--output", "/export"), ("--unknown", "yes")] {
            let mut input = args(); input.extend([key.into(), value.into()]);
            assert!(Plan::parse(&input).is_err(), "{key}");
        }
        for p in ["relative", "/", "/tmp/../file", "/tmp/./file", "/tmp/\nfile"] {
            assert!(path(p).is_err());
        }
    }
}
