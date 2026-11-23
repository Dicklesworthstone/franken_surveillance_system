# Native local S3 object uploads and verification

The archive operator can send one independently identified object to an explicitly approved
local S3-compatible HTTP endpoint. It uses the existing multipart owner, journal and region
authority, without a cloud SDK, external executable, Tokio, DNS, redirects or background work.

The endpoint must support SHA-256 multipart checksums and conditional completion. Only pinned
loopback/private addresses with an explicit plaintext approval are admitted. FSS does not yet
authenticate a public-cloud TLS connection in this profile.

## What completion establishes

Before provider work, the command checks the complete regular source file against an independent
SHA-256 digest. The verified bytes remain in memory during transfer. Each uploaded part carries
a SHA-256 checksum; acknowledgements must return that checksum and an opaque ETag. Completion
contains the exact ordered ETags/checksums, uses If-None-Match: *, and verifies the returned
composite SHA-256. An HTTP 200 containing an S3 Error document remains a failure.

This establishes provider acknowledgement of **one assembled object**. It does not publish an
archive graph, encrypt source bytes, prove replica independence, or prove independent
retrievability. The report keeps those claims explicitly false. Source bytes must already have
the protection required by the approved local destination.

## Prepare, retain the pin, resume

Three commands share the same explicit source, route, operation, deadline and original budget:

- **upload-s3-prepare** verifies the source and writes the initial durable owner checkpoint.
  It performs no provider contact and does not read credentials.
- **upload-s3-resume** verifies the retained minimum pin and original intent, then uploads only
  unacknowledged parts and conditionally completes the object.
- **upload-s3-abort** cancels known uncommitted staging. Prepared uploads abort locally without
  source or credential access. Committed objects cannot be aborted.

Preparation is separate so the caller can independently retain its pin before the first remote
effect. Keep the preparation report outside the journal. Preserve newer reported pins as the
workflow advances: an older minimum cannot detect rollback of a later unretained tail.

Example Bash request, with independently approved values substituted for the placeholders:

    common=(
      --source /absolute/path/object.bin
      --source-sha256 sha256:INDEPENDENT_SOURCE_SHA256_HEX
      --source-bytes EXACT_SOURCE_LENGTH
      --journal /absolute/path/new-upload-journal
      --peer 127.0.0.1:9000
      --host 127.0.0.1:9000
      --region us-east-1
      --bucket evidence
      --key objects/EXACT_OBJECT_KEY
      --credentials /absolute/path/private-s3-credentials
      --plaintext-approval sha256:INDEPENDENT_APPROVAL_SHA256_HEX
      --operation operation:unique-archive-object-transfer
      --deadline-ns ORIGINAL_ABSOLUTE_UTC_NANOSECOND_DEADLINE
      --max-memory-bytes 268435456
      --max-wire-bytes 268435456
      --max-requests 128
      --max-local-bytes 1073741824
      --max-local-operations 4000000
    )

    fss-archive upload-s3-prepare "${common[@]}" > preparation.json

Independently retain the successful report, then supply its journal_sequence and journal_head:

    fss-archive upload-s3-resume "${common[@]}" \
      --minimum-sequence RETAINED_SEQUENCE \
      --minimum-root sha256:RETAINED_JOURNAL_ROOT_HEX

Use upload-s3-abort with the same request and pin to abort known staging. The existing
upload-inspect command remains available for read-only inspection using the report's exact
resource and minimum pin.

The private credential file contains two or three LF-terminated lines: access key ID, secret
access key, and optional session token. Credential values never enter argv, reports or
diagnostics. The native credential owner zeroizes owned strings and consumed input. Every
signing boundary requires AdapterAuth for the exact route. Durable native operations require
StagedUpload ownership so authentication-grant narrowing survives recovery.

## Bounds and ownership

The filesystem profile currently supports Linux x86-64 and AArch64. Source files are at most
64 MiB; parts default to 5 MiB and may be configured from 5–64 MiB. Source identity, size and
timestamps are checked around bounded reads. Symlinks, special files, source/credential aliases,
and overlapping journal paths refuse. A wrong source digest refuses before creating a journal.

A separate live I/O owner scopes source, credential and journal access, charging bytes, filesystem
operations and elapsed latency. It has a ten-minute invocation limit. The provider child keeps
the original transfer deadline. Journal access preserves exclusive locking, physical namespace
binding and full-chain verification; copying a journal does not mint another owner.

Transfer allowances include framing, bounded replies, signing/XML work and source-buffer work.
Source work is durably charged before callbacks. The --max-requests option names the existing
upload storage-operation allowance: source reads and reserved cleanup also consume it. Recovery
never replenishes spent allowance. Local filesystem work is separately reported.

Native I/O offers at most 64 KiB per socket operation. Connection, per-I/O and total exchange
deadlines, response-body/wire ceilings and I/O counts are finite. Authority, clock, cancellation
and authentication scope are rechecked at boundaries. No socket or task outlives its owner.

## Failure and recovery

Preparation, completed upload and acknowledged abort return successful exit status with a
complete bounded report. When possible, nonterminal or indeterminate results still emit a
complete report on stdout with a failing exit status.

A lost create/part/complete/abort acknowledgement never implies that the operation did not
happen. The command retains its original uncertain operation and records explicit local
indeterminate settlement, using the pre-settlement journal head as a follow-up reference.
It does not blindly recreate, complete again, or delete a possibly committed object. Cold
reopening of locally settled uncertainty reports that state without credentials or provider I/O.

An uncertain completion can now be observed through the bounded read-only path below. Missing
objects, partial listings and timeouts remain insufficient evidence. Lost initiation, part and
abort acknowledgements still require other conclusive provider evidence before a separate
repair/replacement workflow can be authorized.
An upload interrupted between acknowledged operations can resume using its original upload ID
and confirmed part receipts.

An ambiguous journal write blocks further effects and sets journal_requires_cold_reopen.
Preserve the original directory and independently retained pin. Wrong intent, changed route,
changed original budget ceiling, missing pin, revoked capability or exhausted allowance refuses.

The fss.s3_upload_cli.v1 report carries intent/source/plan identities, pins, acknowledged part
counts, cumulative/remaining transfer work, local work, receipt, uncertainty, local settlement
and next action. Credentials, provider tokens, paths, object keys and source bytes are excluded.

## Observe an indeterminate completion after restart

**upload-s3-reconcile** handles an upload whose complete request became uncertain and whose
local owner was closed as indeterminate. It opens the original journal at an independently
retained minimum pin, validates the exact original intent and complete acknowledged inventory,
and creates a new owner with only network, authentication and status-observation grants.

The new operation has its own finite deadline and explicit allowance. The old upload deadline
may have expired; its original budget is neither enlarged nor spent again. Original identity,
privacy and retention restrictions remain, and persisted network/authentication revocations
still refuse the read. This command does not need the source file's contents.

The native probe sends one signed HEAD with checksum mode enabled. A positive result requires
the exact initiation metadata (intent, plan, root and journal custody origin), complete
multipart SHA-256 checksum and part-count suffix, exact planned length, valid opaque ETag and
unambiguous response framing. A different journal using the same operation/source/route has a
different custody origin, so an older matching object cannot mask its unfinished upload.

The origin is bound before initiation from the verified physical journal namespace and its
first committed record. Copied journals cannot supply another owner. Older uploads made without
this metadata, and unbound/non-durable transports, cannot obtain positive HEAD reconciliation;
they remain unknown even if ordinary intent/checksum metadata matches. No historic checkpoint
format is rewritten or upgraded by observing it.

Supply the same original source identity, source path, route, part size and **upload operation**.
The deadline and transfer bounds on this command authorize the **new observation**. Choose a
distinct observation operation and a new receipt pathname outside the original journal, source
and credential paths. Its parent directory must already exist:

    fss-archive upload-s3-reconcile \
      --source /absolute/path/object.bin \
      --source-sha256 sha256:INDEPENDENT_SOURCE_SHA256_HEX \
      --source-bytes EXACT_SOURCE_LENGTH \
      --journal /absolute/path/original-upload-journal \
      --peer 127.0.0.1:9000 --host 127.0.0.1:9000 \
      --region us-east-1 --bucket evidence --key objects/EXACT_OBJECT_KEY \
      --credentials /absolute/path/private-s3-credentials \
      --plaintext-approval sha256:INDEPENDENT_APPROVAL_SHA256_HEX \
      --operation operation:original-archive-object-transfer \
      --deadline-ns FRESH_ABSOLUTE_UTC_NANOSECOND_DEADLINE \
      --max-memory-bytes 16777216 --max-wire-bytes 2097152 --max-requests 1 \
      --max-local-bytes 1073741824 --max-local-operations 4000000 \
      --minimum-sequence RETAINED_SEQUENCE \
      --minimum-root sha256:RETAINED_JOURNAL_ROOT_HEX \
      --observation-operation operation:independent-completion-observation \
      --observation-receipt /absolute/path/new-observation.bin

If the original plan used a nondefault part size, include the same --part-bytes value.
The receipt is canonical binary data, at most 64 KiB, with strict decode/reencoding through
CompletionObservationReceipt. It binds the source journal head and historical indeterminate
receipt to the exact new authority, time, spend and result. The CLI creates it exclusively with
private permissions, fsyncs it, reads back the exact bytes, verifies stable file identity and
timestamps, and fsyncs its parent. Existing receipts are never overwritten, including after an
ambiguous write.

| Observation result | Meaning | CLI status |
|---|---|---|
| completed | Exact positive evidence establishes the bound object completion; the separate receipt is durably verified. | Success only when local settlement and receipt durability also succeed. |
| unknown | A read was attempted, but missing, denied, conflicting, incomplete or malformed evidence did not prove completion. | Failure, with uncertainty and any durable observation receipt retained. |
| not_observed | No provider observation was admitted, for example because credentials were unavailable. | Failure, with a separately settled receipt where possible. |

The JSON report uses **fss.s3_completion_observation_cli.v1**. It reports old upload spend and
new observation spend separately, the unchanged source pin, old indeterminate proof, observation
and optional completion digests, and whether the receipt is durably confirmed. Unknown and
not_observed never imply that the upload failed, was aborted or can be recreated.

The historical upload owner remains indeterminate even after a positive observation. Retain
the new receipt as the linked completion evidence; upload-s3-resume continues to report the old
owner without contacting the provider. No repeated complete, part upload or abort is permitted
through the observation owner. If delivery or receipt writing fails, retain the original pin
and inspect the new receipt path before authorizing a separate bounded observation. Matching
provider metadata is still distinct from downloading and independently verifying source bytes.

## Independent verification of completed object bytes

`fss-object::uploader::RetrievalObservation` verifies a separately pinned,
locally completed upload through `RetrievalTransport`. A new operation with exactly
`ReadMedia`, `AdapterNet` and `AdapterAuth` grants receives its own finite deadline,
budget, object-store child and drain obligation. It preserves the original principal,
privacy, retention and resource restrictions. The historical upload journal, owner,
deadline and spend remain unchanged; status-only observation authority cannot read media.

The owner accepts objects from 1 byte through 64 MiB. It downloads every byte in
ranges of at most 256 KiB, without crossing original part boundaries, checks every
part against its original acknowledged SHA-256, and computes the complete object
SHA-256 against an independently supplied digest. That digest is a separate input
from the manifest root. It rechecks current authority and deadline after hashing
before recording `Verified`. Returned media buffers are cleared after use, including
failure paths. No source-file read is involved in this verification.

The native S3 reader signs every range and requires HTTP 206, exact length and
Content-Range, exact intent/plan/root/custody-origin metadata, and one strong opaque
ETag across the response sequence. Subsequent requests sign `If-Match`. A changed
object, missing origin, duplicate/conflicting headers, redirect, full-body response,
encoding, short response or wrong bytes cannot produce a verified result. ETags are
representation pins, never substitutes for checksums. A refused transport cannot
silently retry within the same attempt.

The immutable `fss.multipart_retrieval_observation.v1` receipt records the source
journal pin and completion proof, origin, independent digest, expected size/parts,
fresh authority and actual spend, admitted ranges, hashed bytes and verified parts.
Its outcome is `NotObserved`, `Unknown`, `Mismatch` or `Verified`. Failed attempts
still settle the fresh child and preserve their consumed work. Only `Verified`
establishes complete byte equality at the observation time. This is not a restored
file, encryption, graph closure, replica independence, future availability or repair
certificate. Uploads whose original completion remains locally indeterminate are
not yet eligible, even if a separate HEAD observation later succeeds.

### Verify from a cold operator process

`fss-archive upload-s3-verify` exposes this path after restart. Supply the original
source digest/length, upload operation, route, part policy and independently retained
completed-journal pin. The source pathname remains an identity/scope argument, but
the file may be absent. The deadline and transfer ceilings belong to this new read.
Choose a new observation operation and an unused receipt pathname with an existing
parent directory:

    fss-archive upload-s3-verify \
      --source /absolute/path/object.bin \
      --source-sha256 sha256:INDEPENDENT_SOURCE_SHA256_HEX \
      --source-bytes EXACT_SOURCE_LENGTH \
      --journal /absolute/path/original-upload-journal \
      --peer 127.0.0.1:9000 --host 127.0.0.1:9000 \
      --region us-east-1 --bucket evidence --key objects/EXACT_OBJECT_KEY \
      --credentials /absolute/path/private-s3-credentials \
      --plaintext-approval sha256:INDEPENDENT_APPROVAL_SHA256_HEX \
      --operation operation:original-archive-object-transfer \
      --deadline-ns FRESH_ABSOLUTE_UTC_NANOSECOND_DEADLINE \
      --max-memory-bytes 805306368 --max-wire-bytes 268435456 --max-requests 512 \
      --max-local-bytes 1073741824 --max-local-operations 4000000 \
      --minimum-sequence RETAINED_COMPLETED_SEQUENCE \
      --minimum-root sha256:RETAINED_COMPLETED_JOURNAL_ROOT_HEX \
      --observation-operation operation:independent-object-verification \
      --observation-receipt /absolute/path/new-retrieval-receipt.bin

Include the original `--part-bytes` value when it differs from the 5 MiB default.
The example transfer ceilings cover the admitted 64 MiB profile under default native
response limits; they authorize cumulative work, not allocation of one large buffer.
Smaller explicit ceilings may be chosen using the work formula below.

| Retrieval result | What happened | Exit status |
|---|---|---|
| verified | Every original part and the independent whole-object digest matched under current read authority. | Success only after fresh-owner settlement and durable receipt verification. |
| mismatch | Returned length or computed bytes contradicted the retained independent evidence. | Failure; original upload remains unchanged. |
| unknown | A range was admitted, but provider, framing, scope, clock or budget checks prevented complete verification. | Failure; partial counts and charged work remain explicit. |
| not_observed | No range was admitted, for example because credentials were unavailable. | Failure; a fresh local receipt is retained where possible. |

The closed [JSON report schema](../schemas/s3_retrieval_observation_cli.v1.json) is
`fss.s3_retrieval_observation_cli.v1`. It separates the verification outcome from
`observation_receipt_durable`. A failed receipt write cannot yield a successful
command even if byte verification completed. Inspect an ambiguously created receipt
before choosing a different receipt path; the command never overwrites one.

The completion observer's guidance to retain its receipt and pursue independent
retrievability describes the remaining workflow goal. That receipt is not currently
an input to `upload-s3-verify`: the original upload must itself have a locally
verified completion. Neither a HEAD result nor a successful byte read reopens an
old upload owner or grants graph publication, repair or deletion authority.

### Bounded work model

This implements a single-object verification component of `COST-RETRIEVE-001`;
the broader sampling/scheduling/repair operation remains unqualified. For part
lengths `p_i`, range width `R = 262144`, and total bytes `B`, one complete attempt
admits `N = sum(ceil(p_i / R))` read operations and hashes `2B` bytes: one pass for
part checksums and one for the independent whole checksum. Hash state is constant
size; the owner retains only the current range. It does not allocate the whole object.

With default native transport limits, each range additionally reserves 2,260,992
bytes of bounded response/signing/framing work and 540,672 wire bytes before socket
creation. Thus the explicit transfer allowance needs at least `B + N * 2,260,992`
in its bytes dimension, `N * 540,672` network bytes and `N` storage operations.
These are cumulative conservative admissions, not measured peak resident memory or
latency promises. Credential, journal and receipt filesystem work uses its separate
local budget. Failed requests remain charged, and exhausting any dimension stops
before the next provider request.

## Implementation and validation

Production code is in fss-reference::s3_upload, StagedUpload::try_upload_chunks, and the
fss-archive S3 command/I/O modules. Focused regressions cover signing against AWS's published
vector, real loopback multipart traffic, authority/budget refusal, cold journal recovery,
source failures, private filesystem scope, process-level success/abort and HTTP 200 error bodies.

Protocol references:
[SigV4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html),
[CreateMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html),
[UploadPart](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html), and
[CompleteMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html),
and [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).
Independent range verification follows
[GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).

Source and executable validation are recorded separately in the session handoff. Authored tests
do not establish live MinIO/NAS/B2/R2/AWS compatibility or complete the broader FSS-064 archive
reconciliation and retrievability requirements.

## Independent byte verification

Use **verify-s3-object** after retaining the original object's full SHA-256 and byte length.
This command actually reads and hashes the remote bytes. It does not treat a successful upload,
HEAD response, ETag or multipart composite checksum as the independent source identity. It can
also verify an already existing object without any local source file or upload journal.

    fss-archive verify-s3-object \
      --object-sha256 sha256:INDEPENDENT_FULL_OBJECT_SHA256_HEX \
      --object-bytes EXACT_OBJECT_LENGTH \
      --peer 127.0.0.1:9000 --host 127.0.0.1:9000 \
      --region us-east-1 --bucket evidence --key objects/EXACT_OBJECT_KEY \
      --credentials /absolute/path/private-s3-credentials \
      --plaintext-approval sha256:INDEPENDENT_APPROVAL_SHA256_HEX \
      --operation operation:independent-object-verification \
      --deadline-ns NEW_ABSOLUTE_UTC_NANOSECOND_DEADLINE \
      --max-memory-bytes 600000000 --max-wire-bytes 150000000 \
      --max-requests 256 --max-local-bytes 1048576 --max-local-operations 10000 \
      --receipt /absolute/path/new-verification-receipt.bin

The current CLI profile reads at most **64 MiB** in **256 KiB** ranges. Each nonempty response
must have status 206, the exact Content-Range and Content-Length, no transfer encoding or
content transformation, and one strong quoted ETag. Subsequent GETs sign If-Match with the first
ETag. Every byte contributes to a streaming SHA-256 in source order. A zero-byte object instead
requires one exact empty GET and the independently supplied SHA-256 of the empty byte sequence.
There are no redirects, DNS resolution, retries, listings, uploads or payload exports.

The native API accepts configurable bounded ranges of 1 KiB–1 MiB. A fresh ObjectStore owner
must have **exactly** AdapterNet, AdapterAuth and ReadMedia, each scoped only to the selected
endpoint resource; metadata-only observation authority is insufficient. The owner must also
bind its anchor universe to the independent object digest. One finite owner deadline covers
the entire read and is never renewed between ranges. Every attempted request reserves its
conservative memory/wire ceiling and an operation before contact; failed work remains charged.
These byte counters are cumulative reservations, not peak RSS or measured wire utilization.
Use `verification_budget` when embedding the native API to calculate the full required allowance.

Local credential access and immutable receipt custody have a separate path-scoped owner. An
existing, aliased, unsafe or unavailable receipt destination refuses before provider contact.
The command never opens an upload journal. It drains the remote owner on success or refusal
and separately writes, syncs and reads back a new private receipt without overwriting one.

The bounded report uses `fss.s3_object_verification_cli.v1`:

- `object_bytes_verified=true` means the complete stream matched the independently supplied
  object identity at `verified_at_ns`.
- `verification_receipt_durable=true` additionally means immutable local receipt persistence
  succeeded. The report includes its canonical SHA-256. Both claims are required for exit 0.
- If the read fails, the report retains the charged work, gives a payload-free refusal reason,
  and sets receipt digest/time to null. A failure does not prove that the object is absent.
- If bytes verified but receipt persistence failed, the report preserves the byte result,
  sets durability false, and exits unsuccessfully. Inspect any existing receipt before
  authorizing another verification; a partial file is not silently overwritten.

`fss_reference::s3_upload::verification::S3VerificationReceipt::decode` strictly decodes the
bounded canonical receipt and rejects truncation, suffix bytes and invalid shapes. Decoding
creates inert evidence, never execution authority. The receipt contains the independent
object identity, approved endpoint digest, ETag digest, exact read authority recipe, times,
range size and charged ceilings. It contains no object payload, key or credentials.

This establishes a complete read of **one object at that time**. It does not establish archive
graph closure, independent replicas, future availability, client-side encryption or public
TLS support. The original upload journal and its completion/uncertainty outcome remain unchanged.

Focused regressions are in `s3_retrieval_native_contract.rs` and
`archive_s3_verification_process.rs`; they exercise actual loopback sockets and CLI processes,
including corruption, version changes, malformed ranges, private receipt custody and
pre-network authority refusal. They are local fixtures, not external-provider qualification.

The standalone receipt does not certify an original FSS upload's journal, part inventory or
custody-origin metadata. Use the journal-bound RetrievalObservation API above for those
additional historical custody guarantees; neither receipt replaces the other's proof scope.
