#![forbid(unsafe_code)]
//! Exact, bounded S3 GetObject ranges for the independently authorized reader.
//! https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
//! An ETag identifies one representation for If-Match; it is never a digest.

use fss_core::{ContentDigest, DigestAlgorithm, RegionId};
use fss_object::uploader::{MAX_RETRIEVAL_RANGE_BYTES, RetrievalCx, RetrievalTransport};

use super::{NativeS3Transport, S3Clock, S3Error, signing};
use fss_object::multipart::{MultipartPhase, TransportOperation, UploadIntent};

#[derive(Default)]
pub(super) struct ReadState {
    binding: Option<ReadBinding>,
    etag: Option<String>,
    next_offset: u64,
    refused: bool,
}

struct ReadBinding {
    region: RegionId,
    expected_bytes: u64,
    expected_digest: ContentDigest,
}

/// Only strong quoted entity tags are valid If-Match pins. The provider token
/// stays opaque; accepting weak validators would not bind one representation.
fn strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=1024).contains(&bytes.len())
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == b'!' || (b'#'..=b'~').contains(byte))
}

impl<C: S3Clock> NativeS3Transport<C> {
    fn retrieve_inner(
        &mut self,
        cx: &mut RetrievalCx<'_>,
        intent: &UploadIntent,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, S3Error> {
        let expected_bytes = cx.expected_bytes();
        let expected_digest = cx.expected_digest();
        let cx = cx.transport_context();
        if !cx.is_media_retrieval()
            || self.phase != MultipartPhase::Completed
            || self.retrieval.refused
            || self.intent.as_ref() != Some(intent)
            || self.origin.is_none()
            || self.upload.is_none()
            || self.parts.is_empty()
            || expected_bytes != self.confirmed_bytes
            || expected_digest.algorithm() != DigestAlgorithm::Sha256
            || expected_digest.bytes() == [0; 32]
            || expected_digest.is_laboratory()
        {
            return Err(S3Error::Binding);
        }
        self.check(cx, TransportOperation::Reconcile)?;
        if offset != self.retrieval.next_offset
            || length == 0
            || length > MAX_RETRIEVAL_RANGE_BYTES
            || length > self.limits.response_bytes as u64
        {
            return Err(S3Error::Limit);
        }
        let end = offset.checked_add(length).ok_or(S3Error::Limit)?;
        if end > expected_bytes {
            return Err(S3Error::Limit);
        }
        if let Some(binding) = &self.retrieval.binding {
            if &binding.region != cx.authority().region()
                || binding.expected_bytes != expected_bytes
                || binding.expected_digest != expected_digest
            {
                return Err(S3Error::Binding);
            }
        } else {
            self.retrieval.binding = Some(ReadBinding {
                region: cx.authority().region().clone(),
                expected_bytes,
                expected_digest,
            });
        }
        let mut headers = vec![
            ("range", format!("bytes={offset}-{}", end - 1)),
            ("accept-encoding", "identity".to_owned()),
        ];
        if let Some(etag) = &self.retrieval.etag {
            headers.push(("if-match", etag.clone()));
        }
        let mut response = self.exchange(
            cx,
            "GET",
            "",
            &headers,
            &[],
            ContentDigest::sha256(b""),
            false,
        )?;
        // Neither a full response, redirect, missing object nor failed
        // precondition can supply the requested independently bound range.
        response.status(206)?;
        let origin = self.origin.ok_or(S3Error::Binding)?;
        for (name, expected) in [
            ("content-length", length.to_string()),
            (
                "content-range",
                format!("bytes {offset}-{}/{expected_bytes}", end - 1),
            ),
            (
                "x-amz-meta-fss-intent",
                signing::hex(&intent.digest().bytes()),
            ),
            (
                "x-amz-meta-fss-plan",
                signing::hex(&intent.plan_digest().bytes()),
            ),
            (
                "x-amz-meta-fss-root",
                signing::hex(&intent.manifest_root().bytes()),
            ),
            ("x-amz-meta-fss-origin", signing::hex(&origin.bytes())),
        ] {
            if response.unique_header(name)? != expected {
                return Err(S3Error::Binding);
            }
        }
        if response.0.body.len() as u64 != length
            || !response.0.trailers.is_empty()
            || response.optional_header("transfer-encoding")?.is_some()
            || response.optional_header("content-encoding")?.is_some()
            || response.optional_header("location")?.is_some()
            || response
                .optional_header("x-amz-delete-marker")?
                .is_some_and(|value| value != "false")
        {
            return Err(S3Error::Protocol);
        }
        let etag = response.unique_header("etag")?;
        if !strong_etag(etag)
            || self
                .retrieval
                .etag
                .as_ref()
                .is_some_and(|expected| expected != etag)
        {
            return Err(S3Error::Binding);
        }
        if self.retrieval.etag.is_none() {
            self.retrieval.etag = Some(etag.to_owned());
        }
        self.retrieval.next_offset = end;
        // Transfer only the proved range. Reply clears all retained protocol
        // buffers; the retrieval owner clears returned media after hashing it.
        Ok(std::mem::take(&mut response.0.body))
    }
}

impl<C: S3Clock> RetrievalTransport for NativeS3Transport<C> {
    fn retrieve_range(
        &mut self,
        cx: &mut RetrievalCx<'_>,
        intent: &UploadIntent,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, String> {
        let result = self.retrieve_inner(cx, intent, offset, length);
        if result.is_err() {
            // Even a failed read is a single bounded attempt. A fresh owner and
            // fresh adapter are required for another independently priced read.
            self.retrieval.refused = true;
        }
        result.map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::strong_etag;

    #[test]
    fn representation_validator_is_opaque_and_strong() {
        assert!(strong_etag("\"opaque-whole-token\""));
        assert!(strong_etag("\"multipart-value-7\""));
        for value in [
            "",
            "opaque",
            "\"\"",
            "W/\"weak\"",
            "\"one\",\"two\"",
            "\"space token\"",
            "\"line\ntoken\"",
        ] {
            assert!(!strong_etag(value), "{value:?}");
        }
    }
}
