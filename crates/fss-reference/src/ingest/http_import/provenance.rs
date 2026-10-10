#![forbid(unsafe_code)]
//! Bounded original-wire lineage retained inside an ordinary import publication.

use super::*;
use crate::ingest::http_camera::HttpWireReceipt;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CanonicalDecoder, DigestAlgorithm, Sha256Hasher};

pub(super) fn encode_scope(e: &mut CanonicalEncoder, source: HttpWireScope, pin: HttpWirePin) {
    for bytes in [
        source.stream.source,
        source.receive_clock,
        source.retention_evidence,
    ] {
        e.digest(ContentDigest::new(DigestAlgorithm::Sha256, bytes));
    }
    e.u64(source.stream.generation);
    e.digest(pin.scope);
    e.digest(pin.head);
    e.u64(pin.reads);
    e.u64(pin.bytes);
}
fn read_digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let digest = d.digest()?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(corrupt("digest algorithm"));
    }
    Ok(digest)
}
fn count(
    d: &mut CanonicalDecoder<'_>,
    ceiling: usize,
    minimum_bytes: usize,
) -> Result<usize, FileIngestError> {
    let n = usize::try_from(d.u64()?).map_err(|_| corrupt("count overflow"))?;
    if n > ceiling || n > d.remaining() / minimum_bytes {
        return Err(corrupt("collection bound"));
    }
    Ok(n)
}
impl Proof {
    pub(super) fn encode(&self) -> Result<Vec<u8>, FileIngestError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        encode_scope(&mut e, self.source, self.pin);
        e.digest(self.request);
        e.text(self.sensor.as_str());
        e.text(self.stream.as_str());
        e.i128(self.receive_time.0);
        e.bool(self.assumed_time);
        e.bool(self.ending == HttpImportEnding::ExplicitFramingComplete);
        e.u64(self.roots.len() as u64);
        for origin in &self.roots {
            e.digest(origin.root);
            e.bytes(&origin.manifest);
            e.bytes(&origin.metadata);
        }
        e.u64(self.frames.len() as u64);
        for frame in &self.frames {
            e.digest(frame.encoded);
            e.u64(frame.bytes);
            e.i128(frame.capture.earliest.0);
            e.i128(frame.capture.latest.0);
            e.u64(frame.spans.len() as u64);
            for span in &frame.spans {
                for n in span.wire_range.into_iter().chain(span.jpeg_range) {
                    e.u64(n);
                }
                e.bool(span.chunk.is_some());
                if let Some(n) = span.chunk {
                    e.u64(n);
                }
            }
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("proof size"));
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("proof size"));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN {
            return Err(corrupt("unknown proof"));
        }
        let source_digest = read_digest(&mut d)?;
        let receive_clock = read_digest(&mut d)?;
        let retention = read_digest(&mut d)?;
        let source = HttpWireScope {
            stream: StreamBasis {
                source: source_digest.bytes(),
                generation: d.u64()?,
            },
            receive_clock: receive_clock.bytes(),
            retention_evidence: retention.bytes(),
        };
        let pin = HttpWirePin {
            scope: read_digest(&mut d)?,
            head: read_digest(&mut d)?,
            reads: d.u64()?,
            bytes: d.u64()?,
        };
        let request = read_digest(&mut d)?;
        let sensor = SensorId::parse(d.text()?)?;
        let stream = StreamId::parse(d.text()?)?;
        let receive_time = TimestampNs(d.i128()?);
        let assumed_time = d.bool()?;
        let ending = if d.bool()? {
            HttpImportEnding::ExplicitFramingComplete
        } else {
            HttpImportEnding::PinnedPrefix
        };
        let n = count(&mut d, 4096, 49)?;
        let mut roots = Vec::with_capacity(n);
        for _ in 0..n {
            let root = read_digest(&mut d)?;
            let manifest = d.bytes()?;
            let metadata = d.bytes()?;
            if manifest.len() > 1024 || metadata.len() > 512 {
                return Err(corrupt("original metadata bound"));
            }
            roots.push(WireOrigin {
                root,
                manifest: manifest.to_vec(),
                metadata: metadata.to_vec(),
            });
        }
        let n = count(&mut d, MAX_FRAMES, 81)?;
        let mut frames = Vec::with_capacity(n);
        let mut total_spans = 0usize;
        for _ in 0..n {
            let encoded = read_digest(&mut d)?;
            let bytes = d.u64()?;
            let capture = CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?;
            let count = count(&mut d, MAX_SPANS, 33)?;
            total_spans = total_spans
                .checked_add(count)
                .ok_or_else(|| corrupt("span count"))?;
            if total_spans > MAX_SPANS {
                return Err(corrupt("span count"));
            }
            let mut spans = Vec::with_capacity(count);
            for _ in 0..count {
                let wire_range = [d.u64()?, d.u64()?];
                let jpeg_range = [d.u64()?, d.u64()?];
                let chunk = if d.bool()? { Some(d.u64()?) } else { None };
                spans.push(JpegWireSpan {
                    wire_range,
                    jpeg_range,
                    chunk,
                });
            }
            frames.push(FrameOrigin {
                encoded,
                bytes,
                capture,
                spans,
            });
        }
        d.ensure_finished()?;
        let result = Self {
            source,
            pin,
            request,
            sensor,
            stream,
            receive_time,
            assumed_time,
            ending,
            roots,
            frames,
        };
        if result.encode()? != bytes {
            return Err(corrupt("noncanonical proof"));
        }
        Ok(result)
    }
    fn validate(&self) -> Result<(), FileIngestError> {
        if self.source.digest().map_err(|_| corrupt("scope"))? != self.pin.scope
            || self.pin.head.algorithm() != DigestAlgorithm::Sha256
            || self.request.algorithm() != DigestAlgorithm::Sha256
            || self.roots.iter().any(|d| {
                d.root.algorithm() != DigestAlgorithm::Sha256
                    || d.manifest.len() > 1024
                    || d.metadata.len() > 512
            })
            || self.roots.is_empty()
            || self.roots.len() > 4096
            || self.roots.len() as u64 != self.pin.reads
            || self.roots.last().map(|r| r.root) != Some(self.pin.head)
            || self.pin.bytes == 0
            || self.pin.bytes > MAX_BYTES
            || self.frames.is_empty()
            || self.frames.len() > MAX_FRAMES
            || self.receive_time.0 < 0
        {
            return Err(corrupt("source selection"));
        }
        let mut end = 0;
        let mut total = 0u64;
        let mut spans = 0usize;
        for frame in &self.frames {
            total = total
                .checked_add(frame.bytes)
                .ok_or_else(|| corrupt("media length"))?;
            if frame.encoded.algorithm() != DigestAlgorithm::Sha256
                || frame.bytes == 0
                || frame.bytes > 16 * 1024 * 1024
                || total > MAX_BYTES
                || frame.capture.earliest > frame.capture.latest
                || frame.capture.latest > self.receive_time
                || (!self.assumed_time
                    && frame.capture != CaptureInterval::new(TimestampNs(0), self.receive_time)?)
            {
                return Err(corrupt("frame length or clock"));
            }
            let mut jpeg_end = 0;
            for span in &frame.spans {
                spans += 1;
                if span.wire_range[0] < end
                    || span.wire_range[1] > self.pin.bytes
                    || span.wire_range[1] <= span.wire_range[0]
                    || span.jpeg_range[0] != jpeg_end
                    || span.jpeg_range[1] <= jpeg_end
                    || span.wire_range[1] - span.wire_range[0]
                        != span.jpeg_range[1] - span.jpeg_range[0]
                    || span.chunk == Some(0)
                    || spans > MAX_SPANS
                {
                    return Err(corrupt("noncontiguous or overlapping source map"));
                }
                end = span.wire_range[1];
                jpeg_end = span.jpeg_range[1];
            }
            if jpeg_end != frame.bytes {
                return Err(corrupt("incomplete JPEG map"));
            }
        }
        Ok(())
    }
    pub(super) fn identity(&self) -> Result<ContentDigest, FileIngestError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_mjpeg_import_identity.v1");
        e.digest(ContentDigest::sha256(&self.encode()?));
        Ok(ContentDigest::sha256(&e.finish()))
    }
}

fn proof(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<Option<(ContentDigest, Proof)>, FileIngestError> {
    if manifest.adapter_id != ADAPTER {
        return Ok(None);
    }
    checkpoint(cx)?;
    let hex = manifest
        .adapter_generation
        .strip_prefix(GENERATION)
        .filter(|s| s.len() == 64)
        .ok_or_else(|| corrupt("adapter generation"))?;
    let digest = ContentDigest::parse(&format!("sha256:{hex}"))?;
    let bytes = deployment.publisher().spool().read(digest)?;
    if bytes.len() > MAX_PROOF_BYTES || ContentDigest::sha256(&bytes) != digest {
        return Err(corrupt("proof digest"));
    }
    Ok(Some((digest, Proof::decode(&bytes)?)))
}

fn originals(
    deployment: &ReferenceDeployment,
    proof: &Proof,
    held: Option<&BTreeSet<ContentDigest>>,
    cx: &ReplayCx,
    verify_objects: bool,
) -> Result<Vec<HttpWireReceipt>, FileIngestError> {
    let mut prior = HttpWirePin {
        scope: proof.pin.scope,
        head: proof.pin.scope,
        reads: 0,
        bytes: 0,
    };
    let mut records = Vec::<HttpWireReceipt>::new();
    for origin in &proof.roots {
        checkpoint(cx)?;
        let manifest = ObjectManifest::from_canonical_bytes(&origin.manifest)?;
        let metadata = manifest
            .metadata_digest()
            .ok_or_else(|| corrupt("wire metadata"))?;
        if let Some(held) = held {
            if !held.contains(&origin.root) || manifest.children().iter().any(|d| !held.contains(d))
            {
                return Err(corrupt("original outside import closure"));
            }
        }
        let (next, wire) = super::super::http_archive::detached_read(
            proof.source,
            prior,
            origin.root,
            &origin.manifest,
            &origin.metadata,
        )
        .map_err(|_| corrupt("wire chain"))?;
        if verify_objects {
            if deployment.publisher().spool().read(origin.root)? != origin.manifest
                || deployment.publisher().spool().read(metadata)? != origin.metadata
            {
                return Err(corrupt("original metadata copies"));
            }
        }
        if records
            .last()
            .is_some_and(|last| wire.admitted_ns < last.admitted_ns)
        {
            return Err(corrupt("receive-clock regression"));
        }
        records.push(wire);
        prior = next;
    }
    if prior != proof.pin {
        return Err(corrupt("final pin"));
    }
    Ok(records)
}

pub(crate) fn verify_membership(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    held: &BTreeSet<ContentDigest>,
    capsules: &BTreeMap<&str, ContentDigest>,
    import_hex: &str,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((digest, proof)) = proof(deployment, manifest, cx)? else {
        return Ok(());
    };
    if !held.contains(&digest)
        || hex(proof.identity()?) != import_hex
        || manifest.limits_digest != proof.request
        || manifest.capture_time_label
            != if proof.assumed_time {
                "operator_assumption"
            } else {
                "unknown"
            }
        || manifest.format != "mjpeg"
        || manifest.segment_spans.len() != proof.frames.len()
        || manifest.chunk_bytes != CHUNK_BYTES as u64
        || manifest.detector_evidence
            != format!(
                "native_http_mime:reconstructed_jpeg_stream:original_wire_retained:{}",
                proof.ending.as_str()
            )
        || !manifest.omission_spans.is_empty()
    {
        return Err(corrupt("import and proof binding"));
    }
    originals(deployment, &proof, Some(held), cx, false)?;
    let mut end = 0;
    for (index, (frame, span)) in proof.frames.iter().zip(&manifest.segment_spans).enumerate() {
        checkpoint(cx)?;
        if span.segment_index != index
            || span.offset != end
            || span.len != frame.bytes
            || span.segment_sha256 != frame.encoded
            || span.gap_before
            || span.capsule_id.as_str() != format!("capsule:{import_hex}:{index:06}")
        {
            return Err(corrupt("frame binding"));
        }
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        let digest = capsules
            .get(object.as_str())
            .ok_or_else(|| corrupt("capsule authority"))?;
        let capsule = SensorCapsule {
            capsule_id: span.capsule_id.clone(),
            sensor_id: proof.sensor.clone(),
            stream_id: proof.stream.clone(),
            sequence: index as u64,
            capture: frame.capture,
            receive_time: proof.receive_time,
            clock_basis: ClockBasis::Estimated,
            source_digest: frame.encoded,
            source_bytes: frame.bytes,
            gap_before: false,
            frame_count: 1,
        };
        if ContentDigest::sha256(&capsule.canonical_bytes()) != *digest {
            return Err(corrupt("sensor, clock or capsule rebinding"));
        }
        end += span.len;
    }
    if end != manifest.input_bytes {
        return Err(corrupt("media tiling"));
    }
    Ok(())
}

/// Re-read original read objects and compare each JPEG byte before decoding or exporting it.
pub(crate) fn verify_segment_budgeted(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    index: usize,
    bytes: &[u8],
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<(), FileIngestError> {
    let Some((_, proof)) = proof(deployment, manifest, cx)? else {
        return Ok(());
    };
    let records = originals(deployment, &proof, None, cx, false)?;
    let frame = proof
        .frames
        .get(index)
        .ok_or_else(|| corrupt("frame index"))?;
    if bytes.len() as u64 != frame.bytes || ContentDigest::sha256(bytes) != frame.encoded {
        return Err(corrupt("reconstructed JPEG"));
    }
    verify_frame(
        deployment,
        &records,
        frame,
        Some(bytes),
        cx,
        &mut None,
        reserve,
    )
}

fn verify_frame(
    deployment: &ReferenceDeployment,
    records: &[HttpWireReceipt],
    frame: &FrameOrigin,
    reconstructed: Option<&[u8]>,
    cx: &ReplayCx,
    cache: &mut Option<(ContentDigest, Vec<u8>)>,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<(), FileIngestError> {
    let mut hash = Sha256Hasher::new();
    for span in &frame.spans {
        let mut cursor = span.wire_range[0];
        let mut jpeg = span.jpeg_range[0] as usize;
        let first = records.partition_point(|r| r.range[1] <= cursor);
        for record in records.iter().skip(first) {
            if cursor == span.wire_range[1] {
                break;
            }
            checkpoint(cx)?;
            if cursor < record.range[0] || cursor >= record.range[1] {
                return Err(corrupt("missing original span"));
            }
            let digest = ContentDigest::new(DigestAlgorithm::Sha256, record.sha256);
            if cache.as_ref().is_none_or(|(held, _)| *held != digest) {
                reserve(record.range[1] - record.range[0])?;
                let source = deployment.publisher().spool().read(digest)?;
                if source.len() as u64 != record.range[1] - record.range[0]
                    || ContentDigest::sha256(&source) != digest
                {
                    return Err(corrupt("original bytes"));
                }
                *cache = Some((digest, source));
            }
            let source = &cache.as_ref().ok_or_else(|| corrupt("original cache"))?.1;
            let end = span.wire_range[1].min(record.range[1]);
            let n = (end - cursor) as usize;
            let original = source
                .get((cursor - record.range[0]) as usize..(end - record.range[0]) as usize)
                .ok_or_else(|| corrupt("original range"))?;
            if reconstructed.is_some_and(|bytes| Some(original) != bytes.get(jpeg..jpeg + n)) {
                return Err(corrupt("JPEG differs from original wire"));
            }
            hash.update(original);
            cursor = end;
            jpeg += n;
        }
        if cursor != span.wire_range[1] {
            return Err(corrupt("truncated wire map"));
        }
    }
    if ContentDigest::new(DigestAlgorithm::Sha256, hash.finalize()?) != frame.encoded {
        return Err(corrupt("original JPEG digest"));
    }
    Ok(())
}

/// Full custody verification includes headers, delimiters and a partial trailing frame.
pub(crate) fn verify_originals(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((_, proof)) = proof(deployment, manifest, cx)? else {
        return Ok(());
    };
    let records = originals(deployment, &proof, None, cx, true)?;
    for record in &records {
        checkpoint(cx)?;
        let digest = ContentDigest::new(DigestAlgorithm::Sha256, record.sha256);
        let bytes = deployment.publisher().spool().read(digest)?;
        if bytes.len() as u64 != record.range[1] - record.range[0]
            || ContentDigest::sha256(&bytes) != digest
        {
            return Err(corrupt("original bytes"));
        }
    }
    let mut cache = None;
    for frame in &proof.frames {
        verify_frame(
            deployment,
            &records,
            frame,
            None,
            cx,
            &mut cache,
            &mut |_| Ok(()),
        )?;
    }
    Ok(())
}
