#![forbid(unsafe_code)]
//! Tests of the real report/file boundary. These opaque fixtures intentionally make no
//! native-recording claim; adapter tests separately exercise actual AVC/HEVC source replay.

use super::*;
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
struct Allowed;
impl Clock for Allowed {
    fn check(&self) -> Result<()> {
        Ok(())
    }
}

struct Fixture {
    root: PathBuf,
    scope: Scope,
    completion: String,
    pin: ContentDigest,
    source: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn limits() -> Limits {
    Limits {
        windows: 8,
        files: 64,
        file_bytes: 16 * 1024 * 1024,
        read_bytes: 64 * 1024 * 1024,
        io_calls: 100_000,
        window_bytes: 32 * 1024 * 1024,
    }
}
impl Fixture {
    fn new(name: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("fss-copied-export-{}-{name}", std::process::id()));
        fs::create_dir(&root)?;
        let scope = Scope {
            codec: "hevc",
            sensor: "sensor-fixture".to_owned(),
            stream: "stream-fixture".to_owned(),
            generation: 1,
            anchor: ContentDigest::sha256(b"anchor"),
            receive_clock: ContentDigest::sha256(b"receive"),
            decode_clock: ContentDigest::sha256(b"decode"),
            time_scale: 90_000,
            namespace: ContentDigest::sha256(b"namespace"),
        };
        let snapshot = ContentDigest::sha256(b"original snapshot claim");
        let parts: [&[u8]; 5] = [
            b"original source packets",
            b"initialization",
            b"native media",
            b"index",
            b"opaque manifest fixture",
        ];
        let root_digest = ContentDigest::sha256(parts[4]);
        let prefix = format!("window-0000000000000000-{}", &root_digest.to_text()[7..]);
        let mut files = Vec::new();
        let mut descriptors = Vec::new();
        let suffixes = [
            "source.bin",
            "init.mp4",
            "media.m4s",
            "index.bin",
            "root.bin",
            "playback.mp4",
        ];
        let playback = [parts[1], parts[2]].concat();
        let mut file_bytes = 0;
        for (bytes, suffix) in parts.into_iter().chain([playback.as_slice()]).zip(suffixes) {
            let filename = format!("{prefix}.{suffix}");
            fs::write(root.join(&filename), bytes)?;
            files.push(format!(
                "{{\"file\":\"{filename}\",\"bytes\":{},\"sha256\":\"{}\"}}",
                bytes.len(),
                ContentDigest::sha256(bytes)
            ));
            if descriptors.len() < 4 {
                descriptors.push(format!(
                    "{{\"sha256\":\"{}\",\"bytes\":{}}}",
                    ContentDigest::sha256(bytes),
                    bytes.len()
                ));
            }
            file_bytes += bytes.len();
        }
        let native_bytes: usize = parts.iter().map(|bytes| bytes.len()).sum();
        let request = format!(
            "{{\"schema\":\"fss.local_archive_export_intent.v1\",\"snapshot\":\"{snapshot}\",\"codec\":\"hevc\",\"query\":[0,100],\"whole_windows_authorized\":true,\"max_export_bytes\":8388608,\"completion_file\":\"COMPLETE.json\"}}\n"
        );
        fs::write(root.join("REQUEST.json"), &request)?;
        let completion = format!(
            "{{\"schema\":\"fss.local_archive_operator_report.v1\",\"command\":\"export\",\"codec\":\"hevc\",\"snapshot\":\"{snapshot}\",\"namespace\":\"{}\",\"sensor\":\"{}\",\"stream\":\"{}\",\"generation\":1,\"anchor\":\"{}\",\"receive_clock\":\"{}\",\"decode_clock\":\"{}\",\"time_scale\":90000,\"durable_windows\":1,\"indexed_windows\":1,\"pages\":1,\"source_replay_on_recovery\":true,\"coverage_claim\":\"not_claimed\",\"time_basis\":\"owner_declared_decode_ticks\",\"query\":[0,100],\"whole_window_selection_bytes\":{native_bytes},\"unindexed\":[],\"verified\":[{{\"ordinal\":0,\"root\":\"{root_digest}\",\"requested_interval\":[0,100],\"returned_decode_interval\":[0,100],\"whole_window_bytes\":{native_bytes},\"objects_source_init_media_index\":[{}],\"exported_files\":[{}]}}],\"range_read_completed\":true,\"verified_windows\":1,\"verified_payload_bytes\":{native_bytes},\"export_payload_bytes_excluding_completion\":{},\"whole_windows_authorized\":true,\"source_may_include_boundary_lookahead\":true,\"completion_file\":\"COMPLETE.json\",\"complete\":true}}\n",
            scope.namespace,
            scope.sensor,
            scope.stream,
            scope.anchor,
            scope.receive_clock,
            scope.decode_clock,
            descriptors.join(","),
            files.join(","),
            file_bytes + request.len(),
        );
        let pin = ContentDigest::sha256(completion.as_bytes());
        fs::write(root.join("COMPLETE.json"), &completion)?;
        // A transported copy need not preserve the source exporter's hard-link topology.
        fs::write(root.join("COMPLETE.json.pending"), &completion)?;
        Ok(Self {
            root,
            scope,
            completion,
            pin,
            source: format!("{prefix}.source.bin"),
        })
    }
    fn rewrite(&mut self, completion: String) -> TestResult {
        self.pin = ContentDigest::sha256(completion.as_bytes());
        self.completion = completion;
        fs::write(self.root.join("COMPLETE.json"), &self.completion)?;
        fs::write(self.root.join("COMPLETE.json.pending"), &self.completion)?;
        Ok(())
    }
    fn open<'a>(&self, limits: Limits, clock: &'a dyn Clock) -> Result<Bundle<'a>> {
        Bundle::open(&self.root, self.pin, &self.scope, limits, clock)
    }
}

#[test]
fn copied_files_verify_without_any_original_archive_and_pending_may_be_a_copy() -> TestResult {
    let fixture = Fixture::new("copy-only")?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    let window = bundle.next_window()?.ok_or("missing window")?;
    assert_eq!(window.source, b"original source packets");
    assert_eq!(window.initialization, b"initialization");
    assert_eq!(window.media, b"native media");
    assert_eq!(window.index, b"index");
    assert_eq!(window.manifest, b"opaque manifest fixture");
    let native_bytes = window.window.bytes;
    assert_eq!(window.window.ordinal, 0);
    assert_eq!(window.window.requested, 0..100);
    assert!(bundle.next_window()?.is_none());
    let receipt = bundle.finish()?;
    assert_eq!(receipt.windows, 1);
    assert_eq!(receipt.recording_bytes, native_bytes);
    assert_eq!(
        receipt.snapshot_claim,
        ContentDigest::sha256(b"original snapshot claim")
    );
    assert_eq!(receipt.query, 0..100);
    assert!(receipt.io_calls > 0 && receipt.io_calls <= limits().io_calls);
    assert_eq!(receipt.files, 9);
    assert!(receipt.pending_copy_present);
    assert_eq!(
        receipt.charged_read_bytes,
        2 * (receipt.file_bytes + receipt.files as u64)
    );
    fs::remove_file(fixture.root.join("COMPLETE.json.pending"))?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(bundle.next_window()?.is_some());
    assert!(!bundle.finish()?.pending_copy_present);
    Ok(())
}

#[test]
fn unpublished_missing_or_inconsistent_completion_never_succeeds() -> TestResult {
    let fixture = Fixture::new("incomplete")?;
    fs::remove_file(fixture.root.join("COMPLETE.json"))?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::Incomplete)
    ));
    fs::write(fixture.root.join("COMPLETE.json"), &fixture.completion)?;
    fs::write(fixture.root.join("COMPLETE.json.pending"), b"partial")?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::Integrity)
    ));
    Ok(())
}

#[test]
fn independent_pin_codec_and_scope_are_required() -> TestResult {
    let fixture = Fixture::new("scope")?;
    assert!(matches!(
        Bundle::open(
            &fixture.root,
            ContentDigest::sha256(b"wrong pin"),
            &fixture.scope,
            limits(),
            &Allowed
        ),
        Err(ExportVerificationError::CompletionPinMismatch)
    ));
    for scope in [
        Scope {
            codec: "avc",
            ..fixture.scope.clone()
        },
        Scope {
            generation: 2,
            ..fixture.scope.clone()
        },
        Scope {
            receive_clock: ContentDigest::sha256(b"other epoch"),
            ..fixture.scope.clone()
        },
    ] {
        assert!(matches!(
            Bundle::open(&fixture.root, fixture.pin, &scope, limits(), &Allowed),
            Err(ExportVerificationError::ScopeMismatch)
        ));
    }
    Ok(())
}

#[test]
fn unknown_names_missing_children_and_corrupt_bytes_refuse() -> TestResult {
    let fixture = Fixture::new("file-faults")?;
    fs::write(fixture.root.join("foreign"), b"")?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::InventoryMismatch)
    ));
    fs::remove_file(fixture.root.join("foreign"))?;
    let original = fs::read(fixture.root.join(&fixture.source))?;
    fs::remove_file(fixture.root.join(&fixture.source))?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::MissingFile)
    ));
    let mut damaged = original;
    damaged[0] ^= 1;
    fs::write(fixture.root.join(&fixture.source), damaged)?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(matches!(
        bundle.next_window(),
        Err(ExportVerificationError::Integrity)
    ));
    Ok(())
}

#[test]
fn report_path_substitution_unknown_fields_duplicate_keys_and_role_drift_refuse() -> TestResult {
    for case in 0..4 {
        let mut fixture = Fixture::new(&format!("report-fault-{case}"))?;
        let replacement = match case {
            0 => fixture.completion.replace(&fixture.source, "../outside"),
            1 => fixture.completion.replacen('{', "{\"unknown\":true,", 1),
            2 => fixture
                .completion
                .replacen('{', "{\"schema\":\"duplicate\",", 1),
            _ => fixture.completion.replace(
                "\"requested_interval\":[0,100]",
                "\"requested_interval\":[1,100]",
            ),
        };
        fixture.rewrite(replacement)?;
        assert!(matches!(
            fixture.open(limits(), &Allowed),
            Err(ExportVerificationError::InvalidReport)
        ));
    }
    Ok(())
}

#[test]
fn request_is_consistency_checked_but_its_observed_digest_is_not_the_completion_pin() -> TestResult
{
    let fixture = Fixture::new("request-scope")?;
    let original = fs::read_to_string(fixture.root.join("REQUEST.json"))?;
    // Reservation is ancillary in v1; same-width valid change is not authenticated by COMPLETE.
    let changed = original.replace("8388608", "8388609");
    fs::write(fixture.root.join("REQUEST.json"), &changed)?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(bundle.next_window()?.is_some());
    let receipt = bundle.finish()?;
    assert_eq!(receipt.completion, fixture.pin);
    assert_eq!(
        receipt.request_observation,
        ContentDigest::sha256(changed.as_bytes())
    );
    fs::write(
        fixture.root.join("REQUEST.json"),
        original.replace("[0,100]", "[1,100]"),
    )?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::InvalidReport)
    ));
    Ok(())
}

#[test]
fn full_four_mib_report_profile_preserves_valid_existing_exports() -> TestResult {
    let mut fixture = Fixture::new("large-report")?;
    let padded = " ".repeat(2 * 1024 * 1024) + &fixture.completion;
    fixture.rewrite(padded)?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(bundle.next_window()?.is_some());
    assert_eq!(bundle.finish()?.windows, 1);
    Ok(())
}

#[test]
fn aggregate_read_allowance_is_not_refilled_for_final_reverification() -> TestResult {
    let fixture = Fixture::new("read-budget")?;
    let mut bytes = 0;
    let mut files = 0;
    for entry in fs::read_dir(&fixture.root)? {
        bytes += entry?.metadata()?.len();
        files += 1;
    }
    let allowance = Limits {
        read_bytes: bytes + files,
        ..limits()
    };
    let mut bundle = fixture.open(allowance, &Allowed)?;
    assert!(bundle.next_window()?.is_some());
    assert!(matches!(
        bundle.finish(),
        Err(ExportVerificationError::Limit("read_bytes"))
    ));
    assert!(matches!(
        fixture.open(
            Limits {
                files: 1,
                ..limits()
            },
            &Allowed
        ),
        Err(ExportVerificationError::Limit("files"))
    ));
    assert!(matches!(
        fixture.open(
            Limits {
                file_bytes: 1,
                ..limits()
            },
            &Allowed
        ),
        Err(ExportVerificationError::Limit("file_bytes"))
    ));
    assert!(matches!(
        fixture.open(
            Limits {
                io_calls: 1,
                ..limits()
            },
            &Allowed
        ),
        Err(ExportVerificationError::Limit("io_calls"))
    ));
    Ok(())
}

#[test]
fn cancellation_deadline_and_changed_files_do_not_emit_completion() -> TestResult {
    struct Controlled(Cell<bool>);
    impl Clock for Controlled {
        fn check(&self) -> Result<()> {
            if self.0.get() {
                Err(ExportVerificationError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    struct Expired;
    impl Clock for Expired {
        fn check(&self) -> Result<()> {
            Err(ExportVerificationError::Deadline)
        }
    }
    let fixture = Fixture::new("drift-cancel")?;
    let clock = Controlled(Cell::new(false));
    let mut bundle = fixture.open(limits(), &clock)?;
    assert!(bundle.next_window()?.is_some());
    clock.0.set(true);
    assert!(matches!(
        bundle.finish(),
        Err(ExportVerificationError::Cancelled)
    ));
    assert!(matches!(
        fixture.open(limits(), &Expired),
        Err(ExportVerificationError::Deadline)
    ));
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(bundle.next_window()?.is_some());
    let mut bytes = fs::read(fixture.root.join(&fixture.source))?;
    bytes[0] ^= 1;
    fs::write(fixture.root.join(&fixture.source), bytes)?;
    assert!(matches!(
        bundle.finish(),
        Err(ExportVerificationError::Changed)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinks_and_subdirectories_are_rejected_before_payload_reads() -> TestResult {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new("symlink-socket")?;
    let source = fixture.root.join(&fixture.source);
    fs::remove_file(&source)?;
    symlink("/dev/zero", &source)?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::UnsafePath)
    ));
    fs::remove_file(&source)?;
    fs::create_dir(&source)?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::UnsafePath)
    ));
    Ok(())
}

fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => {
            assert!(value.is_ascii());
            format!("{value:?}")
        }
        Value::Array(items) => {
            format!("[{}]", items.iter().map(json).collect::<Vec<_>>().join(","))
        }
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!("{key:?}:{}", json(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}
fn fields(value: &mut Value) -> &mut BTreeMap<String, Value> {
    match value {
        Value::Object(fields) => fields,
        _ => panic!("test fixture object"),
    }
}
fn numeric(value: u64) -> Value {
    Value::Number(value.to_string())
}
fn interval_value(start: u64, end: u64) -> Value {
    Value::Array(vec![numeric(start), numeric(end)])
}

#[test]
fn empty_selected_export_is_complete_without_claiming_footage_or_coverage() -> TestResult {
    let mut fixture = Fixture::new("zero-windows")?;
    let mut report = json_input::parse(&fixture.completion)?;
    let object = fields(&mut report);
    object.insert("verified".to_owned(), Value::Array(Vec::new()));
    object.insert(
        "unindexed".to_owned(),
        Value::Array(vec![interval_value(0, 100)]),
    );
    for key in [
        "verified_windows",
        "verified_payload_bytes",
        "whole_window_selection_bytes",
    ] {
        object.insert(key.to_owned(), numeric(0));
    }
    object.insert(
        "export_payload_bytes_excluding_completion".to_owned(),
        numeric(fs::metadata(fixture.root.join("REQUEST.json"))?.len()),
    );
    for entry in fs::read_dir(&fixture.root)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("window-") {
            fs::remove_file(entry.path())?;
        }
    }
    fixture.rewrite(json(&report))?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(bundle.next_window()?.is_none());
    let receipt = bundle.finish()?;
    assert_eq!(receipt.windows, 0);
    assert_eq!(receipt.recording_bytes, 0);
    assert_eq!(receipt.query, 0..100);
    Ok(())
}

#[test]
fn ordered_multiple_windows_preserve_exact_gap_metadata() -> TestResult {
    let mut fixture = Fixture::new("ordered-gaps")?;
    let mut report = json_input::parse(&fixture.completion)?;
    let object = fields(&mut report);
    let original = object
        .get("verified")
        .and_then(Value::array)
        .ok_or("rows")?[0]
        .clone();
    let mut first = original.clone();
    fields(&mut first).insert("returned_decode_interval".to_owned(), interval_value(0, 30));
    fields(&mut first).insert("requested_interval".to_owned(), interval_value(0, 30));
    let mut second = original;
    let second_fields = fields(&mut second);
    let old_root = second_fields
        .get("root")
        .and_then(Value::text)
        .ok_or("root")?
        .to_owned();
    let mut manifest = b"opaque manifest fixture".to_vec();
    manifest[0] ^= 1;
    let new_root = ContentDigest::sha256(&manifest).to_text();
    second_fields.insert("ordinal".to_owned(), numeric(2));
    second_fields.insert("root".to_owned(), Value::Text(new_root.clone()));
    second_fields.insert(
        "returned_decode_interval".to_owned(),
        interval_value(70, 100),
    );
    second_fields.insert("requested_interval".to_owned(), interval_value(70, 100));
    let mut added_bytes = 0;
    let Value::Array(files) = second_fields.get_mut("exported_files").ok_or("files")? else {
        return Err("files array".into());
    };
    for file in files {
        let descriptor = fields(file);
        let old_name = descriptor
            .get("file")
            .and_then(Value::text)
            .ok_or("name")?
            .to_owned();
        let name = old_name
            .replace("0000000000000000", "0000000000000002")
            .replace(&old_root[7..], &new_root[7..]);
        let bytes = if name.ends_with(".root.bin") {
            descriptor.insert("sha256".to_owned(), Value::Text(new_root.clone()));
            manifest.clone()
        } else {
            fs::read(fixture.root.join(old_name))?
        };
        added_bytes += bytes.len() as u64;
        fs::write(fixture.root.join(&name), bytes)?;
        descriptor.insert("file".to_owned(), Value::Text(name));
    }
    object.insert("verified".to_owned(), Value::Array(vec![first, second]));
    object.insert(
        "unindexed".to_owned(),
        Value::Array(vec![interval_value(30, 70)]),
    );
    object.insert("verified_windows".to_owned(), numeric(2));
    object.insert("durable_windows".to_owned(), numeric(3));
    object.insert("indexed_windows".to_owned(), numeric(3));
    object.insert("pages".to_owned(), numeric(2));
    for key in ["verified_payload_bytes", "whole_window_selection_bytes"] {
        let old = object.get(key).and_then(Value::integer).ok_or("bytes")? as u64;
        object.insert(key.to_owned(), numeric(old * 2));
    }
    let key = "export_payload_bytes_excluding_completion";
    let old = object
        .get(key)
        .and_then(Value::integer)
        .ok_or("export bytes")? as u64;
    object.insert(key.to_owned(), numeric(old + added_bytes));
    fixture.rewrite(json(&report))?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert_eq!(
        bundle.next_window()?.ok_or("first")?.window.requested,
        0..30
    );
    assert_eq!(
        bundle.next_window()?.ok_or("second")?.window.requested,
        70..100
    );
    assert!(bundle.next_window()?.is_none());
    assert_eq!(bundle.finish()?.windows, 2);
    fixture.rewrite(
        fixture
            .completion
            .replace("\"unindexed\":[[30,70]]", "\"unindexed\":[]"),
    )?;
    assert!(matches!(
        fixture.open(limits(), &Allowed),
        Err(ExportVerificationError::InvalidReport)
    ));
    Ok(())
}

#[test]
fn hash_consistent_playback_must_still_equal_exact_init_and_media() -> TestResult {
    let mut fixture = Fixture::new("playback-integrity")?;
    let name = fixture.source.replace(".source.bin", ".playback.mp4");
    let mut bytes = fs::read(fixture.root.join(&name))?;
    let old = ContentDigest::sha256(&bytes);
    bytes[0] ^= 1;
    let new = ContentDigest::sha256(&bytes);
    fs::write(fixture.root.join(name), bytes)?;
    fixture.rewrite(fixture.completion.replace(&old.to_text(), &new.to_text()))?;
    let mut bundle = fixture.open(limits(), &Allowed)?;
    assert!(matches!(
        bundle.next_window(),
        Err(ExportVerificationError::Integrity)
    ));
    Ok(())
}

#[test]
fn held_directory_reads_refuse_a_replaced_bundle_path() -> TestResult {
    let fixture = Fixture::new("directory-swap")?;
    let bundle = fixture.open(limits(), &Allowed)?;
    let moved = fixture.root.with_extension("held");
    fs::rename(&fixture.root, &moved)?;
    fs::create_dir(&fixture.root)?;
    let result = bundle.finish();
    fs::remove_dir(&fixture.root)?;
    fs::rename(&moved, &fixture.root)?;
    // No windows read is itself incomplete; opening then consuming a window checks the path.
    assert!(matches!(result, Err(ExportVerificationError::Incomplete)));
    let mut bundle = fixture.open(limits(), &Allowed)?;
    fs::rename(&fixture.root, &moved)?;
    fs::create_dir(&fixture.root)?;
    let result = bundle.next_window();
    fs::remove_dir(&fixture.root)?;
    fs::rename(&moved, &fixture.root)?;
    assert!(matches!(result, Err(ExportVerificationError::Changed)));
    Ok(())
}
