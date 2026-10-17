#![forbid(unsafe_code)]
//! Explicitly approved pre-picture RTP/RTCP custody over the native capture command.
//! Pure parsing; defaults never turn on extra retention or alter ordinary capture.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, PathBuf};

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_object::SpoolLimits;
use fss_publication::LocalPublicationLimits;
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramScope,
};

use super::{driver, plan::Options};

pub(super) const HELP: &str = "fss-capture-rtsp retain-source [ordinary single-capture options]\n\
  --source-root NEW_ABSOLUTE_DIRECTORY --source-retention-evidence sha256:HEX\n\
  [--max-datagrams 8192] [--source-storage-bytes 268435456] [--source-work 1000000000]\n\
\n\
Without --approve this is a pure preview; use its OUTER approval to execute.\n\
The third directory must be new and separate from archive, pins and credentials.\n\
This opt-in retains COMPLETE RTP/RTCP datagrams, including probation, duplicates,\n\
malformed packets and incomplete pictures, before further media progress.\n\
It does not retain RTSP messages, credentials, TCP framing or partial datagrams.\n\
Source storage is UNENCRYPTED and needs its own privacy/retention approval.\n\
It adds a separately priced finite spool and work allowance; limits STOP capture.\n\
There is no rollover, deletion, automatic retry or reconnect in this mode.\n\
Preserve each datagram_durable prefix receipt and the source directory. Such a\n\
receipt survives process loss but is NOT a recording, codec checkpoint or EOF.\n\
Original SDP/codec configuration and timing evidence remain independent inputs\n\
for later reconstruction; an incomplete source prefix is never padded to a frame.\n";

#[derive(Debug)]
pub(super) struct SourceConfig {
    pub(super) root: PathBuf,
    pub(super) scope: DatagramScope,
    pub(super) limits: DatagramArchiveLimits,
    pub(super) storage: LocalPublicationLimits,
    pub(super) work: u64,
}
impl SourceConfig {
    pub(super) fn digest(&self, options: &Options) -> Result<ContentDigest, &'static str> {
        let mut e = CanonicalEncoder::new();
        // Extend the existing capture-approval family; never a new durable media format.
        e.text(super::plan::FORMAT);
        e.text("retain-complete-interleaved-source:separate-spool:no-reconnect:v1");
        e.digest(options.digest()?);
        e.text(self.root.to_str().ok_or("UTF-8 source path required")?);
        e.digest(self.scope.digest().map_err(|_| "invalid source scope")?);
        for n in [
            self.limits.max_datagrams as u64,
            self.limits.max_payload_bytes,
            self.limits.max_scan_roots as u64,
            self.limits.max_spool_object_bytes as u64,
            self.storage.max_roots as u64,
            self.storage.max_children as u64,
            self.storage.max_tombstones as u64,
            self.storage.max_scan_entries as u64,
            self.storage.spool.max_objects as u64,
            self.storage.spool.max_total_bytes,
            self.storage.spool.max_object_bytes as u64,
            self.storage.spool.max_scan_entries as u64,
            self.work,
        ] {
            e.u64(n);
        }
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| "source approval bound")?,
        ))
    }
    pub(super) fn report(&self) -> String {
        object(&[
            ("source_root", string(&self.root.to_string_lossy())),
            (
                "source_scope",
                self.scope
                    .digest()
                    .map_or_else(|_| "null".into(), |d| string(&d.to_text())),
            ),
            (
                "retention_evidence",
                string(&self.scope.retention_evidence.to_text()),
            ),
            ("rtp_channel", self.scope.channels.0.to_string()),
            ("rtcp_channel", self.scope.channels.1.to_string()),
            ("max_datagrams", self.limits.max_datagrams.to_string()),
            (
                "max_payload_bytes",
                self.limits.max_payload_bytes.to_string(),
            ),
            (
                "storage_bytes_reserved",
                self.storage.spool.max_total_bytes.to_string(),
            ),
            ("max_source_work", self.work.to_string()),
            ("source_encrypted", "false".into()),
            ("control_messages_retained", "false".into()),
            ("complete_datagrams_before_media_progress", "true".into()),
            (
                "process_crash_durability",
                string("acknowledged_datagrams_only"),
            ),
        ])
    }
}

pub(super) struct SourcePlan {
    pub(super) capture: Options,
    pub(super) source: SourceConfig,
}
impl SourcePlan {
    pub(super) fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if args.len() > super::plan::MAX_ARGUMENTS + 10 || args.len() % 2 != 0 {
            return Err("bounded key/value capture arguments required");
        }
        let keys = [
            "--source-root",
            "--source-retention-evidence",
            "--max-datagrams",
            "--source-storage-bytes",
            "--source-work",
        ];
        let mut values = BTreeMap::new();
        let mut native = Vec::new();
        for pair in args.chunks_exact(2) {
            let key = pair[0].to_str().ok_or("UTF-8 option required")?;
            let value = pair[1].to_str().ok_or("UTF-8 option value required")?;
            if key.len() > 4096 || value.len() > 4096 {
                return Err("option size bound");
            }
            if keys.contains(&key) {
                if value.is_empty() || values.insert(key, value).is_some() {
                    return Err("empty or duplicate source option");
                }
            } else {
                native.extend_from_slice(pair);
            }
        }
        let capture = Options::parse(&native)?;
        let root = absolute(
            values
                .get("--source-root")
                .copied()
                .ok_or("--source-root required")?,
        )?;
        for other in [&capture.root, &capture.pins] {
            if root.starts_with(other) || other.starts_with(&root) {
                return Err("source, archive and pins must be separate nonnested directories");
            }
        }
        if let Some(auth) = &capture.authentication
            && (root.starts_with(&auth.credential_file) || auth.credential_file.starts_with(&root))
        {
            return Err("source directory must be separate from credentials");
        }
        let evidence = ContentDigest::parse(
            values
                .get("--source-retention-evidence")
                .copied()
                .ok_or("explicit RTP and RTCP --source-retention-evidence required")?,
        )
        .map_err(|_| "invalid retention evidence")?;
        if evidence.algorithm() != DigestAlgorithm::Sha256 || evidence.bytes() == [0; 32] {
            return Err("nonzero SHA-256 retention evidence required");
        }
        let number = |key, default, low, high| -> Result<u64, &'static str> {
            let n = match values.get(key) {
                None => default,
                Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
                    text.parse::<u64>().map_err(|_| "source bound overflow")?
                }
                _ => return Err("unsigned source bound required"),
            };
            if n < low || n > high {
                return Err("source bound exceeded");
            }
            Ok(n)
        };
        let count = number("--max-datagrams", 8192, 1, 65_536)? as usize;
        let total = number(
            "--source-storage-bytes",
            256 * 1024 * 1024,
            65_536,
            1024 * 1024 * 1024,
        )?;
        let work = number("--source-work", 1_000_000_000, 1, 100_000_000_000)?;
        let scope = DatagramScope {
            binding: capture.binding(),
            channels: capture.live_config().protocol.channels,
            receive_clock: capture.recording_config().scope.receive_clock,
            retention_evidence: evidence,
        };
        let limits = DatagramArchiveLimits {
            max_datagrams: count,
            max_payload_bytes: capture.max_received_bytes(),
            max_scan_roots: 2 * count + 16,
            max_spool_object_bytes: 65_536,
        };
        let storage = LocalPublicationLimits::new(
            count,
            2,
            count,
            2 * count + 16,
            SpoolLimits::new(3 * count + 16, total, 65_536, 3 * count + 16),
        );
        storage
            .validate()
            .map_err(|_| "source spool bounds refused")?;
        DatagramArchive::new(scope.clone(), limits).map_err(|_| "source archive bounds refused")?;
        let source = SourceConfig {
            root,
            scope,
            limits,
            storage,
            work,
        };
        source.digest(&capture)?;
        Ok(Self { capture, source })
    }
    pub(super) fn approved(&self) -> bool {
        self.capture.approve.is_some()
    }
    pub(super) fn preview(&self) -> Result<String, &'static str> {
        Ok(object(&[
            ("schema", string(super::plan::FORMAT)),
            ("phase", string("planned")),
            ("mode", string("retain-source")),
            (
                "approval",
                string(&self.source.digest(&self.capture)?.to_text()),
            ),
            ("source_custody", self.source.report()),
            ("capture_plan", self.capture.preview()?),
            ("effects_started", "false".into()),
        ]))
    }
    pub(super) fn execute(&self) -> Result<(), &'static str> {
        driver::execute_retained(&self.capture, &self.source)
    }
}

fn absolute(text: &str) -> Result<PathBuf, &'static str> {
    let p = PathBuf::from(text);
    if !p.is_absolute()
        || p.parent().is_none()
        || text.chars().any(char::is_control)
        || text.split('/').any(|p| matches!(p, "." | ".."))
        || p.components()
            .any(|p| matches!(p, Component::CurDir | Component::ParentDir))
    {
        return Err("non-root absolute source path without dot components required");
    }
    Ok(p)
}
