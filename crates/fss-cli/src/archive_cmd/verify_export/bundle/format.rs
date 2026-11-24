#![forbid(unsafe_code)]
//! Closed parsing of the versioned exporter output; metadata never selects a codec.

use super::*;

type Object = BTreeMap<String, Value>;
fn invalid<T>() -> Result<T> {
    Err(ExportVerificationError::InvalidReport)
}
fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Object> {
    let object = value
        .object()
        .ok_or(ExportVerificationError::InvalidReport)?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return invalid();
    }
    Ok(object)
}
fn field<'a>(object: &'a Object, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or(ExportVerificationError::InvalidReport)
}
fn text<'a>(object: &'a Object, key: &str) -> Result<&'a str> {
    field(object, key)?
        .text()
        .ok_or(ExportVerificationError::InvalidReport)
}
fn number(value: &Value) -> Result<u64> {
    let Value::Number(raw) = value else {
        return invalid();
    };
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid();
    }
    raw.parse()
        .map_err(|_| ExportVerificationError::InvalidReport)
}
fn integer(object: &Object, key: &str) -> Result<u64> {
    number(field(object, key)?)
}
fn truth(object: &Object, key: &str) -> Result<()> {
    if field(object, key)?.boolean() != Some(true) {
        return invalid();
    }
    Ok(())
}
fn exact(object: &Object, key: &str, expected: &str) -> Result<()> {
    if text(object, key)? != expected {
        return invalid();
    }
    Ok(())
}
fn hash(object: &Object, key: &str) -> Result<ContentDigest> {
    let raw = text(object, key)?;
    let digest = ContentDigest::parse(raw).map_err(|_| ExportVerificationError::InvalidReport)?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.to_text() != raw {
        return invalid();
    }
    Ok(digest)
}
fn range(value: &Value) -> Result<Range<u64>> {
    let values = value
        .array()
        .ok_or(ExportVerificationError::InvalidReport)?;
    if values.len() != 2 {
        return invalid();
    }
    let start = number(&values[0])?;
    let end = number(&values[1])?;
    if start >= end {
        return invalid();
    }
    Ok(start..end)
}
fn array<'a>(object: &'a Object, key: &str) -> Result<&'a [Value]> {
    field(object, key)?
        .array()
        .ok_or(ExportVerificationError::InvalidReport)
}
fn checked_add(total: u64, value: u64) -> Result<u64> {
    total
        .checked_add(value)
        .ok_or(ExportVerificationError::Limit("file_bytes"))
}

pub(super) fn document(value: &Value, scope: &Scope, limits: Limits) -> Result<Document> {
    let mut fields = vec![
        "schema",
        "command",
        "codec",
        "snapshot",
        "namespace",
        "sensor",
        "stream",
        "generation",
        "anchor",
        "receive_clock",
        "decode_clock",
        "time_scale",
        "durable_windows",
        "indexed_windows",
        "pages",
        "source_replay_on_recovery",
        "coverage_claim",
        "time_basis",
        "query",
        "whole_window_selection_bytes",
        "unindexed",
        "verified",
        "range_read_completed",
        "verified_windows",
        "verified_payload_bytes",
        "export_payload_bytes_excluding_completion",
        "whole_windows_authorized",
        "source_may_include_boundary_lookahead",
        "completion_file",
        "complete",
    ];
    let header = value
        .object()
        .ok_or(ExportVerificationError::InvalidReport)?;
    let request_digest = match text(header, "schema")? {
        EXPORT_COMPLETION_SCHEMA => {
            fields.push("request_sha256");
            Some(hash(header, "request_sha256")?)
        }
        "fss.local_archive_operator_report.v1" => None,
        _ => return invalid(),
    };
    let object = object(value, &fields)?;
    exact(object, "command", "export")?;
    exact(object, "coverage_claim", "not_claimed")?;
    exact(object, "time_basis", "owner_declared_decode_ticks")?;
    exact(object, "completion_file", "COMPLETE.json")?;
    for key in [
        "complete",
        "range_read_completed",
        "source_replay_on_recovery",
        "whole_windows_authorized",
        "source_may_include_boundary_lookahead",
    ] {
        truth(object, key)?;
    }
    if !matches!(scope.codec, "avc" | "hevc")
        || text(object, "codec")? != scope.codec
        || text(object, "sensor")? != scope.sensor
        || text(object, "stream")? != scope.stream
        || integer(object, "generation")? != scope.generation
        || scope.generation == 0
        || hash(object, "anchor")? != scope.anchor
        || hash(object, "receive_clock")? != scope.receive_clock
        || hash(object, "decode_clock")? != scope.decode_clock
        || hash(object, "namespace")? != scope.namespace
        || integer(object, "time_scale")? != u64::from(scope.time_scale)
        || scope.time_scale == 0
    {
        return Err(ExportVerificationError::ScopeMismatch);
    }
    let snapshot = hash(object, "snapshot")?;
    let query = range(field(object, "query")?)?;
    let durable = integer(object, "durable_windows")?;
    let indexed = integer(object, "indexed_windows")?;
    let pages = integer(object, "pages")?;
    let rows = array(object, "verified")?;
    if rows.len() > limits.windows {
        return Err(ExportVerificationError::Limit("windows"));
    }
    if durable > MAX_WINDOWS as u64
        || indexed > durable
        || pages > indexed
        || (indexed == 0) != (pages == 0)
        || rows.len() as u64 > indexed
        || integer(object, "verified_windows")? != rows.len() as u64
    {
        return invalid();
    }
    let mut windows = Vec::with_capacity(rows.len());
    let mut roots = BTreeSet::new();
    let mut previous_ordinal = None;
    let mut previous_end = None;
    let mut cursor = query.start;
    let mut unindexed = Vec::new();
    let mut recording_bytes = 0;
    for row in rows {
        let window = window(row, &query, limits)?;
        if window.ordinal as u64 >= indexed
            || previous_ordinal.is_some_and(|last| window.ordinal <= last)
            || previous_end.is_some_and(|last| window.returned.start < last)
            || !roots.insert(window.root)
        {
            return invalid();
        }
        if cursor < window.requested.start {
            unindexed.push(cursor..window.requested.start);
        }
        cursor = window.requested.end;
        previous_ordinal = Some(window.ordinal);
        previous_end = Some(window.returned.end);
        recording_bytes = checked_add(recording_bytes, window.bytes)?;
        windows.push(window);
    }
    if cursor < query.end {
        unindexed.push(cursor..query.end);
    }
    let reported_gaps = array(object, "unindexed")?;
    if reported_gaps.len() != unindexed.len() {
        return invalid();
    }
    for (reported, expected) in reported_gaps.iter().zip(&unindexed) {
        if range(reported)? != *expected {
            return invalid();
        }
    }
    if integer(object, "whole_window_selection_bytes")? != recording_bytes
        || integer(object, "verified_payload_bytes")? != recording_bytes
    {
        return invalid();
    }
    Ok(Document {
        request_digest,
        snapshot,
        query,
        windows,
        recording_bytes,
        exported_bytes: integer(object, "export_payload_bytes_excluding_completion")?,
    })
}

fn window(value: &Value, query: &Range<u64>, limits: Limits) -> Result<Window> {
    let row = object(
        value,
        &[
            "ordinal",
            "root",
            "requested_interval",
            "returned_decode_interval",
            "whole_window_bytes",
            "objects_source_init_media_index",
            "exported_files",
        ],
    )?;
    let ordinal = usize::try_from(integer(row, "ordinal")?)
        .map_err(|_| ExportVerificationError::InvalidReport)?;
    if ordinal >= MAX_WINDOWS {
        return invalid();
    }
    let root = hash(row, "root")?;
    let requested = range(field(row, "requested_interval")?)?;
    let returned = range(field(row, "returned_decode_interval")?)?;
    if requested != (query.start.max(returned.start)..query.end.min(returned.end)) {
        return invalid();
    }
    let bytes = integer(row, "whole_window_bytes")?;
    if bytes == 0 || bytes > limits.window_bytes as u64 {
        return Err(ExportVerificationError::Limit("window_bytes"));
    }
    let objects = array(row, "objects_source_init_media_index")?;
    let exported = array(row, "exported_files")?;
    if objects.len() != 4 || exported.len() != 6 {
        return invalid();
    }
    let text = root.to_text();
    let prefix = format!("window-{ordinal:016x}-{}", &text[7..]);
    let suffixes = [
        "source.bin",
        "init.mp4",
        "media.m4s",
        "index.bin",
        "root.bin",
        "playback.mp4",
    ];
    let mut files = Vec::with_capacity(6);
    for (file, suffix) in exported.iter().zip(suffixes) {
        let fields = object(file, &["file", "bytes", "sha256"])?;
        let name = format!("{prefix}.{suffix}");
        exact(fields, "file", &name)?;
        let bytes = integer(fields, "bytes")?;
        if bytes > limits.window_bytes as u64 {
            return Err(ExportVerificationError::Limit("window_bytes"));
        }
        files.push(FileDescriptor {
            name,
            bytes,
            digest: hash(fields, "sha256")?,
        });
    }
    for (object_value, file) in objects.iter().zip(&files) {
        let fields = object(object_value, &["sha256", "bytes"])?;
        if hash(fields, "sha256")? != file.digest || integer(fields, "bytes")? != file.bytes {
            return invalid();
        }
    }
    let total = files[..5]
        .iter()
        .try_fold(0, |sum, file| checked_add(sum, file.bytes))?;
    if total != bytes
        || files[4].digest != root
        || files[5].bytes != checked_add(files[1].bytes, files[2].bytes)?
    {
        return invalid();
    }
    Ok(Window {
        ordinal,
        root,
        requested,
        returned,
        bytes,
        files,
    })
}

pub(super) fn request(bytes: &[u8], doc: &Document, scope: &Scope, limits: Limits) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ExportVerificationError::InvalidReport)?;
    let value = json_input::parse(text).map_err(|_| ExportVerificationError::InvalidReport)?;
    let fields = object(
        &value,
        &[
            "schema",
            "snapshot",
            "codec",
            "query",
            "whole_windows_authorized",
            "max_export_bytes",
            "completion_file",
        ],
    )?;
    exact(fields, "schema", "fss.local_archive_export_intent.v1")?;
    exact(fields, "codec", scope.codec)?;
    exact(fields, "completion_file", "COMPLETE.json")?;
    truth(fields, "whole_windows_authorized")?;
    let reservation = doc
        .recording_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(json_input::MAX_ARCHIVE_EXPORT_REPORT_BYTES as u64 + 4096))
        .ok_or(ExportVerificationError::InvalidReport)?;
    let maximum = 2 * MAX_WINDOWS as u64 * limits.window_bytes as u64
        + json_input::MAX_ARCHIVE_EXPORT_REPORT_BYTES as u64
        + 4096;
    let budget = integer(fields, "max_export_bytes")?;
    if hash(fields, "snapshot")? != doc.snapshot
        || range(field(fields, "query")?)? != doc.query
        || budget < reservation
        || budget > maximum
    {
        return invalid();
    }
    Ok(())
}
