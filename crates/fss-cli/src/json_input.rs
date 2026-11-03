#![forbid(unsafe_code)]
//! CLI file/stdin boundary for the shared first-party bounded JSON parser.
//!
//! The pure parser lives in `fss_core`; this compatibility re-export preserves the established
//! CLI input API and keeps ambient file/stdin access out of the semantic core.

pub use fss_core::json_input::{
    JsonError, MAX_INPUT_BYTES, Value, parse, parse_reconstruction_atlas_report,
    parse_retained_supervisor_report,
};

/// Reads an intent document from a regular file, or from stdin when `path` is `-`.
pub fn read_document(path: &str) -> Result<Value, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin()
            .take(MAX_INPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("stdin cannot be read: {error}"))?;
    } else {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("the file cannot be read: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("the path is not a regular file".to_owned());
        }
        std::fs::File::open(path)
            .and_then(|file| {
                file.take(MAX_INPUT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|error| format!("the file cannot be read: {error}"))?;
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(format!("the document exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let text = String::from_utf8(bytes).map_err(|_| "the document is not UTF-8".to_owned())?;
    parse(&text).map_err(|error| format!("the document is not valid JSON: {error}"))
}
