use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::digest::{CanonicalWriter, Digest, DigestError, domain_digest};

const FILE_MAGIC: &[u8; 8] = b"FSSJNL1\0";
const FRAME_MAGIC: &[u8; 4] = b"FSSF";
const COMMIT_MAGIC: &[u8; 4] = b"FSSC";
const FRAME_FIXED_BYTES: u64 = 4 + 8 + 8 + 32 + 32 + 32;
const COMMIT_BYTES: u64 = 4 + 32;
const MAX_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    RefuseIncomplete,
    RepairIncompleteTail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub sequence: u64,
    pub payload_length: u64,
    pub payload_digest: Digest,
    pub previous_root: Digest,
    pub root: Digest,
    pub committed_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalReceipt {
    pub path: PathBuf,
    pub sequence: u64,
    pub payload_digest: Digest,
    pub root: Digest,
    pub committed_end: u64,
}

impl JournalReceipt {
    #[must_use]
    pub fn render_json(&self) -> String {
        format!(
            "{{\"schema\":\"fss.lab.journal_receipt.v1\",\"path\":\"{}\",\"sequence\":{},\"payload_digest\":\"{}\",\"root\":\"{}\",\"committed_end\":{}}}",
            escape_json(&self.path.to_string_lossy()),
            self.sequence,
            self.payload_digest,
            self.root,
            self.committed_end
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalVerification {
    pub path: PathBuf,
    pub record_count: u64,
    pub root: Digest,
    pub committed_end: u64,
    pub repaired_incomplete_tail: bool,
}

impl JournalVerification {
    #[must_use]
    pub fn render_json(&self) -> String {
        format!(
            "{{\"schema\":\"fss.lab.journal_verification.v1\",\"path\":\"{}\",\"record_count\":{},\"root\":\"{}\",\"committed_end\":{},\"repaired_incomplete_tail\":{}}}",
            escape_json(&self.path.to_string_lossy()),
            self.record_count,
            self.root,
            self.committed_end,
            self.repaired_incomplete_tail
        )
    }
}

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    Digest(DigestError),
    InvalidHeader,
    JournalTooLarge(u64),
    PayloadTooLarge(u64),
    SequenceOverflow,
    SequenceMismatch { expected: u64, observed: u64 },
    PreviousRootMismatch { sequence: u64 },
    PayloadDigestMismatch { sequence: u64 },
    RecordRootMismatch { sequence: u64 },
    CommitTrailerMismatch { sequence: u64 },
    InvalidFrameMagic { offset: u64 },
    IncompleteTail { valid_end: u64, observed_end: u64 },
    LengthOverflow,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "journal I/O failure: {error}"),
            Self::Digest(error) => write!(formatter, "journal digest failure: {error}"),
            Self::InvalidHeader => formatter.write_str("journal header is invalid"),
            Self::JournalTooLarge(bytes) => {
                write!(formatter, "journal size {bytes} exceeds the laboratory bound")
            }
            Self::PayloadTooLarge(bytes) => {
                write!(formatter, "payload size {bytes} exceeds the laboratory bound")
            }
            Self::SequenceOverflow => formatter.write_str("journal sequence overflow"),
            Self::SequenceMismatch { expected, observed } => write!(
                formatter,
                "journal sequence mismatch: expected {expected}, observed {observed}"
            ),
            Self::PreviousRootMismatch { sequence } => {
                write!(formatter, "previous-root mismatch at sequence {sequence}")
            }
            Self::PayloadDigestMismatch { sequence } => {
                write!(formatter, "payload digest mismatch at sequence {sequence}")
            }
            Self::RecordRootMismatch { sequence } => {
                write!(formatter, "record root mismatch at sequence {sequence}")
            }
            Self::CommitTrailerMismatch { sequence } => {
                write!(formatter, "commit trailer mismatch at sequence {sequence}")
            }
            Self::InvalidFrameMagic { offset } => {
                write!(formatter, "invalid frame magic at byte offset {offset}")
            }
            Self::IncompleteTail {
                valid_end,
                observed_end,
            } => write!(
                formatter,
                "journal has an incomplete unpublished tail: valid_end={valid_end}, observed_end={observed_end}"
            ),
            Self::LengthOverflow => formatter.write_str("journal length arithmetic overflow"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DigestError> for JournalError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

#[derive(Debug)]
pub struct EvidenceJournal {
    path: PathBuf,
    file: File,
    entries: Vec<JournalEntry>,
    root: Digest,
    committed_end: u64,
    repaired_incomplete_tail: bool,
}

impl EvidenceJournal {
    pub fn open(path: impl AsRef<Path>, mode: OpenMode) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let length = file.metadata()?.len();
        if length > MAX_JOURNAL_BYTES {
            return Err(JournalError::JournalTooLarge(length));
        }
        if length == 0 {
            file.write_all(FILE_MAGIC)?;
            file.sync_all()?;
        }
        let scan = scan(&mut file)?;
        let repaired_incomplete_tail = if let Some(observed_end) = scan.incomplete_end {
            match mode {
                OpenMode::RefuseIncomplete => {
                    return Err(JournalError::IncompleteTail {
                        valid_end: scan.committed_end,
                        observed_end,
                    });
                }
                OpenMode::RepairIncompleteTail => {
                    file.set_len(scan.committed_end)?;
                    file.sync_all()?;
                    true
                }
            }
        } else {
            false
        };
        file.seek(SeekFrom::Start(scan.committed_end))?;
        Ok(Self {
            path,
            file,
            entries: scan.entries,
            root: scan.root,
            committed_end: scan.committed_end,
            repaired_incomplete_tail,
        })
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<JournalReceipt, JournalError> {
        let payload_length = u64::try_from(payload.len()).map_err(|_| JournalError::LengthOverflow)?;
        if payload_length > MAX_PAYLOAD_BYTES {
            return Err(JournalError::PayloadTooLarge(payload_length));
        }
        let sequence = u64::try_from(self.entries.len())
            .map_err(|_| JournalError::SequenceOverflow)?
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        let payload_digest = domain_digest("fss-journal-payload-v1", payload)?;
        let root = record_root(sequence, self.root, payload_digest)?;
        let frame_end = self
            .committed_end
            .checked_add(FRAME_FIXED_BYTES)
            .and_then(|value| value.checked_add(payload_length))
            .and_then(|value| value.checked_add(COMMIT_BYTES))
            .ok_or(JournalError::LengthOverflow)?;
        if frame_end > MAX_JOURNAL_BYTES {
            return Err(JournalError::JournalTooLarge(frame_end));
        }

        self.file.seek(SeekFrom::Start(self.committed_end))?;
        self.file.write_all(FRAME_MAGIC)?;
        self.file.write_all(&sequence.to_be_bytes())?;
        self.file.write_all(&payload_length.to_be_bytes())?;
        self.file.write_all(&self.root.as_bytes())?;
        self.file.write_all(&payload_digest.as_bytes())?;
        self.file.write_all(&root.as_bytes())?;
        self.file.write_all(payload)?;
        self.file.sync_data()?;
        self.file.write_all(COMMIT_MAGIC)?;
        self.file.write_all(&root.as_bytes())?;
        self.file.sync_data()?;

        self.entries.push(JournalEntry {
            sequence,
            payload_length,
            payload_digest,
            previous_root: self.root,
            root,
            committed_end: frame_end,
        });
        self.root = root;
        self.committed_end = frame_end;
        Ok(JournalReceipt {
            path: self.path.clone(),
            sequence,
            payload_digest,
            root,
            committed_end: frame_end,
        })
    }

    #[must_use]
    pub fn verification(&self) -> JournalVerification {
        JournalVerification {
            path: self.path.clone(),
            record_count: u64::try_from(self.entries.len()).unwrap_or(u64::MAX),
            root: self.root,
            committed_end: self.committed_end,
            repaired_incomplete_tail: self.repaired_incomplete_tail,
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }
}

#[derive(Debug)]
struct ScanResult {
    entries: Vec<JournalEntry>,
    root: Digest,
    committed_end: u64,
    incomplete_end: Option<u64>,
}

fn scan(file: &mut File) -> Result<ScanResult, JournalError> {
    let observed_end = file.metadata()?.len();
    if observed_end < u64::try_from(FILE_MAGIC.len()).map_err(|_| JournalError::LengthOverflow)? {
        return Err(JournalError::InvalidHeader);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 8];
    file.read_exact(&mut header)?;
    if &header != FILE_MAGIC {
        return Err(JournalError::InvalidHeader);
    }
    let mut entries = Vec::new();
    let mut root = Digest::ZERO;
    let mut committed_end = 8_u64;
    loop {
        let frame_offset = file.stream_position()?;
        let mut magic = [0_u8; 4];
        match read_exact_or_incomplete(file, &mut magic)? {
            ReadStatus::End => break,
            ReadStatus::Incomplete => {
                return Ok(ScanResult {
                    entries,
                    root,
                    committed_end,
                    incomplete_end: Some(observed_end),
                });
            }
            ReadStatus::Complete => {}
        }
        if &magic != FRAME_MAGIC {
            return Err(JournalError::InvalidFrameMagic {
                offset: frame_offset,
            });
        }
        let sequence = match read_u64_or_incomplete(file)? {
            Some(value) => value,
            None => return incomplete_scan(entries, root, committed_end, observed_end),
        };
        let expected_sequence = u64::try_from(entries.len())
            .map_err(|_| JournalError::SequenceOverflow)?
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        if sequence != expected_sequence {
            return Err(JournalError::SequenceMismatch {
                expected: expected_sequence,
                observed: sequence,
            });
        }
        let payload_length = match read_u64_or_incomplete(file)? {
            Some(value) => value,
            None => return incomplete_scan(entries, root, committed_end, observed_end),
        };
        if payload_length > MAX_PAYLOAD_BYTES {
            return Err(JournalError::PayloadTooLarge(payload_length));
        }
        let previous_root = match read_digest_or_incomplete(file)? {
            Some(value) => value,
            None => return incomplete_scan(entries, root, committed_end, observed_end),
        };
        if previous_root != root {
            return Err(JournalError::PreviousRootMismatch { sequence });
        }
        let payload_digest = match read_digest_or_incomplete(file)? {
            Some(value) => value,
            None => return incomplete_scan(entries, root, committed_end, observed_end),
        };
        let stored_root = match read_digest_or_incomplete(file)? {
            Some(value) => value,
            None => return incomplete_scan(entries, root, committed_end, observed_end),
        };
        let payload_size = usize::try_from(payload_length).map_err(|_| JournalError::LengthOverflow)?;
        let mut payload = vec![0_u8; payload_size];
        if read_exact_or_incomplete(file, &mut payload)? != ReadStatus::Complete {
            return incomplete_scan(entries, root, committed_end, observed_end);
        }
        let observed_payload_digest = domain_digest("fss-journal-payload-v1", &payload)?;
        if observed_payload_digest != payload_digest {
            return Err(JournalError::PayloadDigestMismatch { sequence });
        }
        let expected_root = record_root(sequence, root, payload_digest)?;
        if stored_root != expected_root {
            return Err(JournalError::RecordRootMismatch { sequence });
        }
        let mut commit_magic = [0_u8; 4];
        if read_exact_or_incomplete(file, &mut commit_magic)? != ReadStatus::Complete {
            return incomplete_scan(entries, root, committed_end, observed_end);
        }
        let committed_root = match read_digest_or_incomplete(file)? {
            Some(value) => value,
            None => return incomplete_scan(entries, root, committed_end, observed_end),
        };
        if &commit_magic != COMMIT_MAGIC || committed_root != expected_root {
            return Err(JournalError::CommitTrailerMismatch { sequence });
        }
        committed_end = file.stream_position()?;
        entries.push(JournalEntry {
            sequence,
            payload_length,
            payload_digest,
            previous_root: root,
            root: expected_root,
            committed_end,
        });
        root = expected_root;
    }
    Ok(ScanResult {
        entries,
        root,
        committed_end,
        incomplete_end: None,
    })
}

fn incomplete_scan(
    entries: Vec<JournalEntry>,
    root: Digest,
    committed_end: u64,
    observed_end: u64,
) -> Result<ScanResult, JournalError> {
    Ok(ScanResult {
        entries,
        root,
        committed_end,
        incomplete_end: Some(observed_end),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStatus {
    Complete,
    End,
    Incomplete,
}

fn read_exact_or_incomplete(file: &mut File, buffer: &mut [u8]) -> Result<ReadStatus, JournalError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) if filled == 0 => return Ok(ReadStatus::End),
            Ok(0) => return Ok(ReadStatus::Incomplete),
            Ok(read) => filled = filled.checked_add(read).ok_or(JournalError::LengthOverflow)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(ReadStatus::Complete)
}

fn read_u64_or_incomplete(file: &mut File) -> Result<Option<u64>, JournalError> {
    let mut bytes = [0_u8; 8];
    if read_exact_or_incomplete(file, &mut bytes)? == ReadStatus::Complete {
        Ok(Some(u64::from_be_bytes(bytes)))
    } else {
        Ok(None)
    }
}

fn read_digest_or_incomplete(file: &mut File) -> Result<Option<Digest>, JournalError> {
    let mut bytes = [0_u8; 32];
    if read_exact_or_incomplete(file, &mut bytes)? == ReadStatus::Complete {
        Ok(Some(Digest::from_bytes(bytes)))
    } else {
        Ok(None)
    }
}

fn record_root(
    sequence: u64,
    previous_root: Digest,
    payload_digest: Digest,
) -> Result<Digest, JournalError> {
    let mut writer = CanonicalWriter::new("fss-journal-record-v1")?;
    writer.push_u64(sequence);
    writer.push_digest(previous_root);
    writer.push_digest(payload_digest);
    Ok(writer.digest()?)
}

fn escape_json(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push('?'),
            value => output.push(value),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{EvidenceJournal, JournalError, OpenMode};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

    fn temporary_path(name: &str) -> std::path::PathBuf {
        let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("fss-lab-{name}-{}-{id}.journal", std::process::id()))
    }

    #[test]
    fn committed_records_reopen_with_the_same_root() {
        let path = temporary_path("reopen");
        let expected = {
            let mut journal = EvidenceJournal::open(&path, OpenMode::RefuseIncomplete)
                .expect("open journal");
            journal.append(b"one").expect("first");
            journal.append(b"two").expect("second").root
        };
        let reopened =
            EvidenceJournal::open(&path, OpenMode::RefuseIncomplete).expect("reopen journal");
        assert_eq!(reopened.verification().root, expected);
        assert_eq!(reopened.entries().len(), 2);
        std::fs::remove_file(path).expect("remove test journal");
    }

    #[test]
    fn incomplete_tail_is_not_published_and_requires_explicit_repair() {
        let path = temporary_path("tail");
        let committed = {
            let mut journal = EvidenceJournal::open(&path, OpenMode::RefuseIncomplete)
                .expect("open journal");
            journal.append(b"one").expect("append").root
        };
        let mut file = OpenOptions::new().append(true).open(&path).expect("append file");
        file.write_all(b"FSSF\0\0").expect("partial frame");
        file.sync_all().expect("sync partial frame");
        assert!(matches!(
            EvidenceJournal::open(&path, OpenMode::RefuseIncomplete),
            Err(JournalError::IncompleteTail { .. })
        ));
        let repaired = EvidenceJournal::open(&path, OpenMode::RepairIncompleteTail)
            .expect("repair incomplete tail");
        assert!(repaired.verification().repaired_incomplete_tail);
        assert_eq!(repaired.verification().root, committed);
        std::fs::remove_file(path).expect("remove test journal");
    }

    #[test]
    fn payload_mutation_is_detected() {
        let path = temporary_path("corruption");
        {
            let mut journal = EvidenceJournal::open(&path, OpenMode::RefuseIncomplete)
                .expect("open journal");
            journal.append(b"evidence").expect("append");
        }
        let mut bytes = std::fs::read(&path).expect("read journal");
        let payload_index = bytes
            .windows(b"evidence".len())
            .position(|window| window == b"evidence")
            .expect("payload present");
        bytes[payload_index] ^= 1;
        std::fs::write(&path, bytes).expect("write corruption");
        assert!(matches!(
            EvidenceJournal::open(&path, OpenMode::RefuseIncomplete),
            Err(JournalError::PayloadDigestMismatch { .. })
        ));
        std::fs::remove_file(path).expect("remove test journal");
    }
}
