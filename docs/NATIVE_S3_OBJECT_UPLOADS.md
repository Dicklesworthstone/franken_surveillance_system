# Native local S3 object uploads

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

This native profile does not yet conclusively reconcile ambiguous remote outcomes. Missing
objects, partial listings and timeouts are insufficient evidence. Independent provider
reconciliation is needed before a separate repair/replacement workflow can be authorized.
An upload interrupted between acknowledged operations can resume using its original upload ID
and confirmed part receipts.

An ambiguous journal write blocks further effects and sets journal_requires_cold_reopen.
Preserve the original directory and independently retained pin. Wrong intent, changed route,
changed original budget ceiling, missing pin, revoked capability or exhausted allowance refuses.

The fss.s3_upload_cli.v1 report carries intent/source/plan identities, pins, acknowledged part
counts, cumulative/remaining transfer work, local work, receipt, uncertainty, local settlement
and next action. Credentials, provider tokens, paths, object keys and source bytes are excluded.

## Implementation and validation

Production code is in fss-reference::s3_upload, StagedUpload::try_upload_chunks, and the
fss-archive S3 command/I/O modules. Focused regressions cover signing against AWS's published
vector, real loopback multipart traffic, authority/budget refusal, cold journal recovery,
source failures, private filesystem scope, process-level success/abort and HTTP 200 error bodies.

Protocol references:
[SigV4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html),
[CreateMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html),
[UploadPart](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html), and
[CompleteMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html).

Source and executable validation are recorded separately in the session handoff. Authored tests
do not establish live MinIO/NAS/B2/R2/AWS compatibility or complete the broader FSS-064 archive
reconciliation and retrievability requirements.
