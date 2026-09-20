#![forbid(unsafe_code)]
//! Create-only, whole-window export. This does not mutate or republish archive roots.
//! A final completion filename appears only after verified payload and receipt writes.
use super::*;
use fss_core::CanonicalEncode;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Component;

pub(super) const MAX_EXPORT_BYTES: u64 = 2 * 4096 * MAX_RECORDING_BYTES as u64 + MAX_REPORT_BYTES as u64 + 4096;
const IO_CHUNK: usize = 64 * 1024;
const MAX_INTERRUPTS: usize = 8;

pub(super) struct Destination {
    root: PathBuf,
    limit: u64,
    written: u64,
}
impl Destination {
    pub(super) fn begin(options: &ArchiveOptions, snapshot: ContentDigest,
        selected_bytes: u64, clock: &impl OperationClock) -> Result<Self>
    {
        // Every window is written once as its five canonical objects, plus the
        // duplicate init+media playback file. Price worst-case bytes BEFORE mkdir.
        let reservation = selected_bytes.checked_mul(2)
            .and_then(|n| n.checked_add(MAX_REPORT_BYTES as u64 + 4096))
            .ok_or(ArchiveCommandError::ExportBudget)?;
        if reservation > options.export_budget { return Err(ArchiveCommandError::ExportBudget); }
        let archive = fs::canonicalize(&options.root).map_err(|e| io_error("canonicalize source", e))?;
        let output = options.output.as_deref().ok_or(ArchiveCommandError::OutputScope)?;
        let root = new_destination(&archive, output)?;
        let query = options.query.as_ref().ok_or(ArchiveCommandError::OutputScope)?;
        clock.check()?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        // All failures after attempting directory creation are conservatively
        // partial/indeterminate export, never permission to delete or overwrite.
        builder.create(&root).map_err(|e| ArchiveCommandError::ExportIncomplete(Box::new(io_error("create export directory", e))))?;
        let mut destination = Self { root, limit: options.export_budget, written: 0 };
        let request = format!("{{\"schema\":\"fss.local_archive_export_intent.v1\",\"snapshot\":{},\"codec\":\"{}\",\"query\":{},\"whole_windows_authorized\":true,\"max_export_bytes\":{},\"completion_file\":\"COMPLETE.json\"}}\n",
            quoted(&snapshot.to_text()), options.codec.name(), interval(query), options.export_budget);
        let result = destination.file("REQUEST.json", request.as_bytes(), clock)
            .and_then(|_| sync_directory(&destination.root))
            .and_then(|()| sync_directory(destination.root.parent().ok_or(ArchiveCommandError::OutputScope)?));
        result.map_err(|e| ArchiveCommandError::ExportIncomplete(Box::new(e)))?;
        Ok(destination)
    }
    pub(super) fn payload_bytes(&self) -> u64 { self.written }

    pub(super) fn window(&mut self, ordinal: usize, recording: &PreparedRecording,
        clock: &impl OperationClock) -> Result<String>
    {
        clock.check()?;
        let text = recording.manifest().root().to_text();
        let hex = text.strip_prefix("sha256:").ok_or(ArchiveError::Metadata)?;
        let prefix = format!("window-{ordinal:016x}-{hex}");
        let mut entries = Vec::new();
        for ((_, _, bytes), suffix) in recording.children().into_iter()
            .zip(["source.bin", "init.mp4", "media.m4s", "index.bin"])
        {
            entries.push(self.file(&format!("{prefix}.{suffix}"), bytes, clock)?);
        }
        let manifest = recording.manifest().canonical_bytes();
        entries.push(self.file(&format!("{prefix}.root.bin"), &manifest, clock)?);
        let objects = recording.objects();
        let length = objects.initialization.len().checked_add(objects.media.len())
            .filter(|n| *n <= MAX_RECORDING_BYTES).ok_or(ArchiveCommandError::ExportBudget)?;
        // One bounded playback buffer. Do NOT concatenate multiple windows or
        // rewrite tfdt, sequence numbers, sample flags, or original NAL payloads.
        let mut playback = Vec::new();
        playback.try_reserve_exact(length).map_err(|_| ArchiveCommandError::ExportBudget)?;
        playback.extend_from_slice(objects.initialization);
        playback.extend_from_slice(objects.media);
        entries.push(self.file(&format!("{prefix}.playback.mp4"), &playback, clock)?);
        Ok(entries.join(","))
    }

    // Returns a descriptor only after exact same-handle readback and file sync.
    fn file(&mut self, name: &str, bytes: &[u8], clock: &impl OperationClock) -> Result<String> {
        clock.check()?;
        if bytes.len() as u64 > self.limit.saturating_sub(self.written) {
            return Err(ArchiveCommandError::ExportBudget);
        }
        let digest = ContentDigest::try_sha256(bytes).map_err(|_| ArchiveCommandError::ExportBudget)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.root.join(name)).map_err(|e| io_error("create export file", e))?;
        write_bounded(&mut file, bytes, clock)?;
        file.sync_all().map_err(|e| io_error("sync export file", e))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| io_error("seek export readback", e))?;
        verify_bytes(&mut file, bytes, clock)?;
        clock.check()?;
        self.written += bytes.len() as u64;
        Ok(format!("{{\"file\":{},\"bytes\":{},\"sha256\":{}}}", quoted(name), bytes.len(), quoted(&digest.to_text())))
    }

    pub(super) fn complete(&mut self, report: &str, clock: &impl OperationClock) -> Result<()> {
        if report.len() > MAX_REPORT_BYTES { return Err(ArchiveCommandError::ReportLimit); }
        self.file("COMPLETE.json.pending", report.as_bytes(), clock)?;
        sync_directory(&self.root)?;
        clock.check()?;
        // Atomic create-only publication, no rename-overwrite race. The pending
        // name remains as a second hard link; it is not an independent success.
        fs::hard_link(self.root.join("COMPLETE.json.pending"), self.root.join("COMPLETE.json"))
            .map_err(|e| io_error("publish completion link", e))?;
        // Cancellation cannot undo this completed publication. A sync error or
        // lost stdout acknowledgement requires explicit inspection of the output.
        sync_directory(&self.root)
    }
}
fn new_destination(archive: &Path, output: &Path) -> Result<PathBuf> {
    if !matches!(output.components().next_back(), Some(Component::Normal(_))) {
        return Err(ArchiveCommandError::OutputScope);
    }
    let parent = output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|e| io_error("canonicalize export parent", e))?;
    if !parent.is_dir() { return Err(ArchiveCommandError::OutputScope); }
    let target = parent.join(output.file_name().ok_or(ArchiveCommandError::OutputScope)?);
    if target.starts_with(archive) || archive.starts_with(&target) { return Err(ArchiveCommandError::OutputScope); }
    match fs::symlink_metadata(&target) {
        Ok(_) => Err(ArchiveCommandError::OutputExists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(e) => Err(io_error("inspect export target", e)),
    }
}
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path).and_then(|f| f.sync_all()).map_err(|e| io_error("sync export directory", e))
}
fn write_bounded(writer: &mut impl Write, mut bytes: &[u8], clock: &impl OperationClock) -> Result<()> {
    let mut interrupted = 0;
    while !bytes.is_empty() {
        clock.check()?;
        let part = &bytes[..bytes.len().min(IO_CHUNK)];
        match writer.write(part) {
            Ok(0) => return Err(io_error("write export", io::Error::from(io::ErrorKind::WriteZero))),
            Ok(n) if n <= part.len() => { bytes = &bytes[n..]; interrupted = 0; }
            Ok(_) => return Err(io_error("write export", io::Error::from(io::ErrorKind::InvalidData))),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted + 1 < MAX_INTERRUPTS => interrupted += 1,
            Err(e) => return Err(io_error("write export", e)),
        }
    }
    Ok(())
}
fn verify_bytes(reader: &mut impl Read, expected: &[u8], clock: &impl OperationClock) -> Result<()> {
    let mut buffer = [0_u8; IO_CHUNK];
    let mut offset = 0; let mut interrupted = 0;
    loop {
        clock.check()?;
        let count = match reader.read(&mut buffer) {
            Ok(n) if n <= buffer.len() => { interrupted = 0; n }
            Ok(_) => return Err(io_error("read export", io::Error::from(io::ErrorKind::InvalidData))),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted + 1 < MAX_INTERRUPTS => { interrupted += 1; continue; }
            Err(e) => return Err(io_error("read export", e)),
        };
        if count == 0 {
            return if offset == expected.len() { Ok(()) } else { Err(ArchiveError::Metadata.into()) };
        }
        if expected.get(offset..offset + count) != Some(&buffer[..count]) { return Err(ArchiveError::Metadata.into()); }
        offset += count;
    }
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
