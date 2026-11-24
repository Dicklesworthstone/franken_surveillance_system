#![forbid(unsafe_code)]
//! A lost non-final part ACK must recover before the process can send the final range.

use super::*;
use std::io;

const PART_BYTES: usize = 5 * 1024 * 1024;
const FINAL_BYTES: &[u8] = b"end";

// This fixture alone needs one legal non-final S3 part. Keep the smaller shared
// oracle's 512 KiB ceiling unchanged and admit at most 5 MiB here.
fn multipart_request(stream: &mut TcpStream) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let end = loop {
        if Instant::now() >= deadline {
            return Err("multipart fixture request deadline".into());
        }
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("truncated multipart request head".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if end + 4 > 16 * 1024 {
                return Err("multipart request header bound".into());
            }
            break end + 4;
        }
        if bytes.len() >= 16 * 1024 {
            return Err("multipart request header bound".into());
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).map_err(|error| error.to_string())?;
    let mut lines = head.split("\r\n");
    let first = lines
        .next()
        .ok_or("missing multipart request line")?
        .to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("malformed multipart header")?;
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err("duplicate multipart request header".into());
        }
    }
    let length: usize = headers
        .get("content-length")
        .ok_or("missing multipart body length")?
        .parse()
        .map_err(|_| "invalid multipart body length")?;
    if length > PART_BYTES || bytes.len() - end > length {
        return Err("multipart request body bound".into());
    }
    bytes
        .try_reserve_exact(length - (bytes.len() - end))
        .map_err(|_| "multipart fixture allocation bound")?;
    while bytes.len() - end < length {
        if Instant::now() >= deadline {
            return Err("multipart fixture body deadline".into());
        }
        let offer = (length - (bytes.len() - end)).min(buffer.len());
        let read = stream
            .read(&mut buffer[..offer])
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("truncated multipart request body".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let body = bytes.split_off(end);
    Ok(Request {
        first,
        headers,
        body,
    })
}

struct MultipartServer {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<Vec<Request>, String>>>,
}

impl MultipartServer {
    fn new(source: Vec<u8>) -> Test<Self> {
        if source.len() != PART_BYTES + FINAL_BYTES.len() {
            return Err("multipart fixture source length".into());
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let peer = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            let first_digest = ContentDigest::sha256(&source[..PART_BYTES]);
            let final_digest = ContentDigest::sha256(&source[PART_BYTES..]);
            let first_checksum = b64(&first_digest.bytes());
            let final_checksum = b64(&final_digest.bytes());
            let mut digest_bytes = Vec::with_capacity(64);
            digest_bytes.extend_from_slice(&first_digest.bytes());
            digest_bytes.extend_from_slice(&final_digest.bytes());
            let composite = b64(&ContentDigest::sha256(&digest_bytes).bytes());
            let mut received = Vec::new();
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    return if received.len() == 5 {
                        Ok(received)
                    } else {
                        Err("multipart oracle stopped before five exact requests".into())
                    };
                }
                if Instant::now() >= deadline {
                    return Err("multipart oracle accept deadline".into());
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let request = multipart_request(&mut stream)?;
                if !request
                    .headers
                    .get("authorization")
                    .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
                    || request.headers.values().any(|value| value.contains(SECRET))
                    || request.headers.get("x-amz-content-sha256")
                        != Some(&ContentDigest::sha256(&request.body).to_text()[7..].to_owned())
                {
                    return Err("multipart signature or secret discipline".into());
                }
                let (headers, body) = match received.len() {
                    0 => {
                        if request.first != "POST /test-archive/object.bin?uploads= HTTP/1.1"
                            || !request.body.is_empty()
                        {
                            return Err("expected one multipart initiation".into());
                        }
                        (
                            String::new(),
                            "<InitiateMultipartUploadResult><Bucket>test-archive</Bucket>\
                             <Key>object.bin</Key><UploadId>two-part-upload</UploadId>\
                             </InitiateMultipartUploadResult>"
                                .to_owned(),
                        )
                    }
                    1 => {
                        if request.first
                            != "PUT /test-archive/object.bin?partNumber=1&uploadId=two-part-upload HTTP/1.1"
                            || request.body.as_slice() != &source[..PART_BYTES]
                            || request.headers.get("x-amz-checksum-sha256") != Some(&first_checksum)
                        {
                            return Err("expected exact first 5 MiB part once".into());
                        }
                        // The provider retains all first-part bytes, then loses its ACK.
                        received.push(request);
                        drop(stream);
                        continue;
                    }
                    2 => {
                        if request.first
                            != "GET /test-archive/object.bin?max-parts=1000&part-number-marker=0&uploadId=two-part-upload HTTP/1.1"
                            || !request.body.is_empty()
                        {
                            return Err(
                                "expected positive bounded inventory before forward work".into()
                            );
                        }
                        (
                            String::new(),
                            format!(
                                "<ListPartsResult><Bucket>test-archive</Bucket><Key>object.bin</Key>\
                                 <UploadId>two-part-upload</UploadId><PartNumberMarker>0</PartNumberMarker>\
                                 <NextPartNumberMarker>1</NextPartNumberMarker><MaxParts>1000</MaxParts>\
                                 <IsTruncated>false</IsTruncated><ChecksumAlgorithm>SHA256</ChecksumAlgorithm>\
                                 <ChecksumType>COMPOSITE</ChecksumType><Part><PartNumber>1</PartNumber>\
                                 <ETag>&quot;opaque-first&quot;</ETag><Size>{PART_BYTES}</Size>\
                                 <ChecksumSHA256>{first_checksum}</ChecksumSHA256></Part></ListPartsResult>"
                            ),
                        )
                    }
                    3 => {
                        if request.first
                            != "PUT /test-archive/object.bin?partNumber=2&uploadId=two-part-upload HTTP/1.1"
                            || request.body.as_slice() != &source[PART_BYTES..]
                            || request.body != FINAL_BYTES
                            || request.headers.get("x-amz-checksum-sha256") != Some(&final_checksum)
                        {
                            return Err(
                                "cold recovery did not send only the final three bytes".into()
                            );
                        }
                        (
                            format!(
                                "ETag: \"opaque-final\"\r\nx-amz-checksum-sha256: {final_checksum}\r\n"
                            ),
                            String::new(),
                        )
                    }
                    4 => {
                        let expected = format!(
                            "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                             <Part><PartNumber>1</PartNumber><ETag>&quot;opaque-first&quot;</ETag>\
                             <ChecksumSHA256>{first_checksum}</ChecksumSHA256></Part>\
                             <Part><PartNumber>2</PartNumber><ETag>&quot;opaque-final&quot;</ETag>\
                             <ChecksumSHA256>{final_checksum}</ChecksumSHA256></Part>\
                             </CompleteMultipartUpload>"
                        );
                        if request.first
                            != "POST /test-archive/object.bin?uploadId=two-part-upload HTTP/1.1"
                            || request.headers.get("if-none-match").map(String::as_str) != Some("*")
                            || request.body != expected.as_bytes()
                        {
                            return Err(
                                "completion lost recovered or newly acknowledged part".into()
                            );
                        }
                        (
                            String::new(),
                            format!(
                                "<CompleteMultipartUploadResult><Bucket>test-archive</Bucket>\
                                 <Key>object.bin</Key><ETag>&quot;two-part-object&quot;</ETag>\
                                 <ChecksumSHA256>{composite}-2</ChecksumSHA256>\
                                 <ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
                            ),
                        )
                    }
                    _ => return Err("unexpected replay, observation or mutation".into()),
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                    body.len(),
                )
                .map_err(|error| error.to_string())?;
                stream.flush().map_err(|error| error.to_string())?;
                received.push(request);
            }
        });
        Ok(Self {
            peer,
            stop,
            worker: Some(worker),
        })
    }

    fn finish(mut self) -> Test<Vec<Request>> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .ok_or("multipart oracle worker absent")?
            .join()
            .map_err(|_| "multipart oracle panicked")?
            .map_err(Into::into)
    }
}

impl Drop for MultipartServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn lost_first_part_ack_reopens_then_sends_only_the_final_range_and_completes_two_parts() -> Test {
    let directory = Directory::new("lost-nonfinal-part")?;
    let mut source = vec![0x5a; PART_BYTES];
    source.extend_from_slice(FINAL_BYTES);
    fs::write(directory.0.join("source"), &source)?;
    let source_digest = ContentDigest::sha256(&source);
    let server = MultipartServer::new(source.clone())?;
    let mut args = arguments(&directory, server.peer, "upload-s3-prepare")?;
    replace_argument(&mut args, "--source-sha256", source_digest.to_text())?;
    replace_argument(&mut args, "--source-bytes", source.len().to_string())?;
    replace_argument(
        &mut args,
        "--max-memory-bytes",
        (64_u64 * 1024 * 1024).to_string(),
    )?;
    replace_argument(
        &mut args,
        "--max-wire-bytes",
        (16_u64 * 1024 * 1024).to_string(),
    )?;
    replace_argument(&mut args, "--max-requests", "9".into())?;
    args.extend(["--part-bytes".into(), PART_BYTES.to_string()]);
    let prepared = run(&args)?;
    assert!(prepared.status.success(), "{prepared:?}");
    let prepared = fields(&prepared)?;
    assert_eq!(
        prepared.get("total_parts").and_then(Value::integer),
        Some(2)
    );
    let resume = with_pin(args, &prepared, "upload-s3-resume")?;
    let completed = run(&resume)?;
    assert!(completed.status.success(), "{completed:?}");
    let completed = fields(&completed)?;
    assert_eq!(
        completed.get("phase").and_then(Value::text),
        Some("completed")
    );
    assert_eq!(
        completed.get("confirmed_parts").and_then(Value::integer),
        Some(2)
    );
    assert_eq!(
        completed.get("total_parts").and_then(Value::integer),
        Some(2)
    );
    assert_eq!(completed.get("locally_settled"), Some(&Value::Bool(true)));
    assert_eq!(
        completed.get("source_digest").and_then(Value::text),
        Some(source_digest.to_text().as_str())
    );
    assert_eq!(
        completed.get("source_verified_this_invocation"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        completed.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(true))
    );
    // Five provider operations plus two source-range reads. Cold recovery must
    // preserve both the lost dispatch's spend and its confirmed range.
    let consumed = completed
        .get("upload_consumed")
        .and_then(Value::object)
        .ok_or("consumed")?;
    let remaining = completed
        .get("upload_remaining")
        .and_then(Value::object)
        .ok_or("remaining")?;
    assert_eq!(
        consumed.get("storageOperations").and_then(Value::integer),
        Some(7)
    );
    assert_eq!(
        remaining.get("storageOperations").and_then(Value::integer),
        Some(2)
    );

    fs::remove_file(directory.0.join("source"))?;
    fs::remove_file(directory.0.join("credentials"))?;
    let cold = run(&resume)?;
    assert!(cold.status.success(), "{cold:?}");
    let cold = fields(&cold)?;
    assert_eq!(cold.get("phase").and_then(Value::text), Some("completed"));
    assert_eq!(
        cold.get("confirmed_parts").and_then(Value::integer),
        Some(2)
    );
    assert_eq!(cold.get("receipt_digest"), completed.get("receipt_digest"));
    assert_eq!(
        cold.get("upload_consumed"),
        completed.get("upload_consumed")
    );
    assert_eq!(
        cold.get("source_verified_this_invocation"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        cold.get("provider_work_requested_this_invocation"),
        Some(&Value::Bool(false))
    );
    let requests = server.finish()?;
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.first.starts_with("PUT "))
            .count(),
        2
    );
    assert_eq!(requests[1].body.len(), PART_BYTES);
    assert_eq!(requests[3].body, FINAL_BYTES);
    Ok(())
}
