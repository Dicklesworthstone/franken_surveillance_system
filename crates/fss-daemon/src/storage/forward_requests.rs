#![forbid(unsafe_code)]
//! Durable retry identity for forwarded batches. These records bind requests to verified
//! receipts; canonical world history remains exclusively in the evidence ledger.
//!
//! A reservation without a completion is deliberately not replayed. The ledger may have
//! committed before the caller lost its receipt, so that cut requires reconciliation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ErrorId};
use fss_ipc::IpcError;

use crate::control::ForwardBatchReceipt;
use crate::error::DaemonError;

const DOMAIN: &str = "fss.daemon.forward_request_record.v1";
const MAGIC: &[u8; 8] = b"FSSFWD01";
const MAX_RECORD_BYTES: u64 = 512;
const CONFLICT: &str = "ERR-IDEMPOTENCY-CONFLICT-001";
const RECONCILE: &str = "ERR-OP-RECONCILIATION-REQUIRED-001";

/// Opened only after the owning storage engine acquired its exclusive writer locks.
/// No history-sized in-memory index is needed: each key addresses two bounded records.
pub(crate) struct ForwardRequestStore {
    dir: PathBuf,
}

impl ForwardRequestStore {
    pub(crate) fn open(root: &Path) -> Result<Self, DaemonError> {
        let dir = root.join("forwarded-requests");
        ensure_private_dir(&dir)?;
        Ok(Self { dir })
    }

    fn paths(&self, key: ContentDigest) -> Result<(PathBuf, PathBuf), DaemonError> {
        let dir = self.dir.join(format!("{:02x}", key.bytes()[0]));
        ensure_private_dir(&dir)?;
        let stem = key.to_text().replace(':', "_");
        Ok((
            dir.join(format!("{stem}.reserved")),
            dir.join(format!("{stem}.committed")),
        ))
    }

    /// Returns the original receipt, or durably claims a fresh key before any mutation.
    pub(crate) fn reserve(
        &self,
        key: ContentDigest,
        request: ContentDigest,
    ) -> Result<Option<ForwardBatchReceipt>, DaemonError> {
        let (pending_path, completed_path) = self.paths(key)?;
        if let Some(pending) = read_record(&pending_path)? {
            pending.check_identity(key, request)?;
            if pending.receipt.is_some() {
                return Err(refused(RECONCILE, "reservation has a completion lifecycle"));
            }
            let Some(completed) = read_record(&completed_path)? else {
                return Err(refused(
                    RECONCILE,
                    "forwarded request was reserved without a verified completion; reconcile its ledger outcome before any retry",
                ));
            };
            completed.check_identity(key, request)?;
            let mut receipt = completed.receipt.ok_or_else(|| {
                refused(RECONCILE, "completion record has a reservation lifecycle")
            })?;
            receipt.replayed = true;
            return Ok(Some(receipt));
        }
        if read_record(&completed_path)?.is_some() {
            return Err(refused(RECONCILE, "completion exists without its reservation"));
        }
        write_new_record(
            &pending_path,
            &Record {
                key,
                request,
                receipt: None,
            },
        )?;
        Ok(None)
    }

    pub(crate) fn complete(
        &self,
        key: ContentDigest,
        request: ContentDigest,
        receipt: ForwardBatchReceipt,
    ) -> Result<(), DaemonError> {
        let (pending_path, completed_path) = self.paths(key)?;
        let pending = read_record(&pending_path)?
            .ok_or_else(|| refused(RECONCILE, "completion has no durable reservation"))?;
        pending.check_identity(key, request)?;
        if pending.receipt.is_some() || receipt.commit_sequence == 0 {
            return Err(refused(RECONCILE, "invalid forwarded completion lifecycle"));
        }
        write_new_record(
            &completed_path,
            &Record {
                key,
                request,
                receipt: Some(receipt),
            },
        )
    }
}

#[derive(Clone, Debug)]
struct Record {
    key: ContentDigest,
    request: ContentDigest,
    receipt: Option<ForwardBatchReceipt>,
}

impl Record {
    fn check_identity(
        &self,
        key: ContentDigest,
        request: ContentDigest,
    ) -> Result<(), DaemonError> {
        if self.key != key || self.request != request {
            return Err(refused(
                CONFLICT,
                "idempotency key is already bound to a different forwarded request",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, DaemonError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.bytes(MAGIC);
        encoder.text(DOMAIN);
        encoder.digest(self.key);
        encoder.digest(self.request);
        encoder.bool(self.receipt.is_some());
        if let Some(receipt) = self.receipt {
            encoder.u64(receipt.commit_sequence);
            encoder.digest(receipt.history_root);
            encoder.digest(receipt.state_root);
        }
        let mut bytes = encoder.finish_checked()?;
        let checksum = ContentDigest::sha256(&bytes);
        bytes.extend_from_slice(&checksum.bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, DaemonError> {
        let invalid = || refused(RECONCILE, "forwarded request record is corrupt or unsupported");
        if bytes.len() < 32 || bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if ContentDigest::sha256(body).bytes().as_slice() != checksum {
            return Err(invalid());
        }
        let mut decoder = CanonicalDecoder::new(body);
        if decoder.bytes().map_err(|_| invalid())? != MAGIC
            || decoder.text().map_err(|_| invalid())? != DOMAIN
        {
            return Err(invalid());
        }
        let key = decoder.digest().map_err(|_| invalid())?;
        let request = decoder.digest().map_err(|_| invalid())?;
        let receipt = if decoder.bool().map_err(|_| invalid())? {
            let commit_sequence = decoder.u64().map_err(|_| invalid())?;
            if commit_sequence == 0 {
                return Err(invalid());
            }
            Some(ForwardBatchReceipt {
                commit_sequence,
                history_root: decoder.digest().map_err(|_| invalid())?,
                state_root: decoder.digest().map_err(|_| invalid())?,
                replayed: false,
            })
        } else {
            None
        };
        decoder.ensure_finished().map_err(|_| invalid())?;
        Ok(Self {
            key,
            request,
            receipt,
        })
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), DaemonError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(DaemonError::io("create_forward_request_dir", err)),
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|err| DaemonError::io("stat_forward_request_dir", err))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(refused(RECONCILE, "forwarded request directory is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(refused(RECONCILE, "forwarded request directory must be owner-only"));
        }
    }
    // Also settle a directory whose creation survived an earlier failed parent sync.
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn read_record(path: &Path) -> Result<Option<Record>, DaemonError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(DaemonError::io("stat_forward_request", err)),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RECORD_BYTES
    {
        return Err(refused(RECONCILE, "forwarded request is not a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(refused(RECONCILE, "forwarded request record must be owner-only"));
        }
    }
    let mut file =
        File::open(path).map_err(|err| DaemonError::io("open_forward_request", err))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| DaemonError::io("read_forward_request", err))?;
    let record = Record::decode(&bytes)?;
    // A prior caller might have lost an fsync result after writing complete bytes. Verify
    // and settle both barriers before exposing a cold receipt as a durable success.
    file.sync_all()
        .map_err(|err| DaemonError::io("sync_forward_request", err))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(Some(record))
}

fn write_new_record(path: &Path, record: &Record) -> Result<(), DaemonError> {
    let bytes = record.encode()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(refused(RECONCILE, "forwarded request is already reserved or completed"));
        }
        Err(err) => return Err(DaemonError::io("create_forward_request", err)),
    };
    // Never unlink a partial record on error: losing ambiguous intent could redispatch
    // an effect after a crash. Recovery remains fail-closed until its outcome is reconciled.
    file.write_all(&bytes)
        .map_err(|err| DaemonError::io("write_forward_request", err))?;
    file.sync_all()
        .map_err(|err| DaemonError::io("sync_forward_request", err))?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), DaemonError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| DaemonError::io("sync_forward_request_directory", err))
}

fn refused(error_id: &str, reason: &str) -> DaemonError {
    match ErrorId::parse(error_id) {
        Ok(error_id) => DaemonError::Ipc(IpcError::Refused {
            request_id: 0,
            error_id,
            reason: reason.to_owned(),
            retryable: false,
        }),
        Err(err) => DaemonError::Contract(err),
    }
}

#[cfg(test)]
mod tests;
