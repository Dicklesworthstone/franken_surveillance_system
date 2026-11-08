# UniFi direct HTTPS snapshot laboratory

This isolated Linux laboratory extends `../unifi_https_auth_lab` with one
authenticated `GET /snap.jpeg`, followed by the FSS pure-Rust MJPEG decoder's
bounded luma reconstruction. It owns the TCP connection through Asupersync
0.5 and FSS task metering, checks network, authentication, status, media-read
and decode grants, and makes at most one login, one status, one settings and
one snapshot request per default run. An explicit `--three-snapshots` option
requests three snapshots over the same session, at least one second apart.
Every JPEG is decoded in memory; only the last may be written to the optional
output. A failed or interrupted sequence is not reported as complete. The
reported adjacent digest changes indicate differences between received JPEG
bytes, not capture times or continuous video. It does not command or replace
the camera's controller. By
default the raw camera image and decoded pixels are held in memory and not
deliberately written to disk or printed. An explicitly authorized optional
output writes the JPEG to a new mode-600 file directly under `/tmp`, then
reads it back and verifies its exact digest. It cannot replace an existing
file; an interrupted or failed write may leave the newly created file. The
file is a laboratory output, not an FSS source-custody or recording receipt.
A decoded frame does not establish capture time or continuity.

The existing credential file, cookie handling and identity caveats are the same
as the neighboring authenticated lab. Credential and response buffers are
cleared on a best-effort basis only; the HTTP decoder, TLS library, JPEG
decoder, allocator and OS may retain copies. The local file access and JPEG
decode are synchronous within the task and are not a production nonblocking
service. The TLS provider is experimental and not admitted; its entropy is
ambient. The observed certificate was collected on the same network and is
not independent proof of physical camera identity. The received JPEG's digest
is computed locally from those same bytes and is not independent origin proof.

On 2026-11-05, the independent loopback TLS fixture served a disposable 16×16
JPEG and verified the login, cookie, status and snapshot request sequence;
the FSS decoder reconstructed it, and no fixture secrets appeared in output.
Three Rust tests on `hz3` covered cookie rejection, strict status JSON and
private-file revocation/permissions. The stripped Linux executable SHA-256 was
`e058b7dac6e4b3e0fbd349abfe7bfbbe94fb814e6637d0e0d8e35a9606d6f5b7`,
and the standalone lockfile SHA-256 was
`dd2361a4289626283b7399ac11203d7d98f1896b16967a49ecfa8228614759cc`.

On `trj`, the changed-certificate and different-valid-key TLS 1.3 controls were
rejected before a deliberately nonexistent credential path could be read. The
matching case then logged into the owner's G4, got HTTP 200 from status and
snapshot, and decoded one 640×360 luma frame directly from the camera. The
camera login created a session whose expiry was not established. The existing
recorder, upload timer and discovery timer were active afterward. This is an
actual direct-camera image decode through the experimental lab, not an
authenticated physical identity, live video stream, sustained recording or
qualification of other models.

A later output-enabled revision, stripped executable SHA-256
`2a0963657d6c12d0dd028217072c6562aeca83ddd83b4ec139f49f75e4161200`,
passed four Rust tests on `hz3` and the independent TLS fixture on `trj`,
including a byte-exact private output and existing-file refusal. Changed-pin
and wrong-key controls stopped before credential access. The matching case
logged into the G4, decoded a 640×360 frame and wrote the exact camera JPEG to
a new private temporary file. A separate private task-workspace copy matched
its SHA-256 and was shown to the owner. The recorder and both timers remained
active. This additionally created one camera login session; its expiry is
unknown. The physical-identity, TLS-provider, custody and continuity limits
above still apply.

The lab now imports the actual `fss_reference::unifi_direct::camera_api`
source for request sequencing and response validation, rather than duplicating
those protocol steps locally. Four contract tests passed on `hz3`; the
independent fixture again completed the sequence. On `trj`, the owner G4
returned HTTP 200 for login, status and one snapshot, which the FSS decoder
reconstructed at 640×360; both TLS negative controls refused before
credential access. The stripped binary SHA-256 was
`9677e491f893a41ee2d311f067399f9308a542f090e58f947d7b4461b1ec8884`.
This was one more camera login session; its expiry was not established. The
same identity, TLS-provider, memory and recording limitations apply.

The project camera API subsequently added a read-only settings request that
retains only the controller-address claim and its peer/generation binding.
An independent TLS fixture with a 60,000-byte settings field reproduced a
TLS deframer `message buffer full` failure in the previous lab binary. A
revision that processes each accepted TLS prefix passed that fixture and then
read the G4's settings on `trj`; its controller claim matched the local source
address of that HTTPS connection. Status and snapshot returned HTTP 200 and
the snapshot decoded at 640×360. Changed-pin and wrong-key controls stopped
before credential access. The corrected stripped executable SHA-256 was
`a581c9a91b2a4d43dec6b4405d1c934bdfe1cd5e6f882eed86c1cd6feb5bc923`.
The initial live attempt failed with the same buffer error; whether it created
a camera session is unknown. The successful attempt created one session, with
unknown expiry. No settings were changed, and the existing recorder and both
timers remained active. This observation is not a complete rollback plan or
independent identity proof.

```text
cargo test --locked --manifest-path experiments/unifi_https_snapshot_lab/Cargo.toml
python3 experiments/unifi_https_snapshot_lab/fixture.py BIN CERT_DER CERT_PEM KEY_PEM JPEG_FIXTURE
```

The binary takes `CERT_DER PRIVATE_IPV4 tls13 match SCOPE_DIGEST
CREDENTIAL_FILE 443 --owner-authorized`. The scope must explicitly include
the snapshot and in-memory decode. To request a viewable output, insert an
explicit `/tmp/fss-unifi-snapshot-*.jpg` path before `--owner-authorized` and
include that exact destination in the scope. A loopback-only fixture can use
another port. No credential or camera image belongs in a repository fixture.
Place the optional `--three-snapshots` immediately before `--owner-authorized`
and include all three reads and decodes in the owner-authorized scope. The
fixture accepts `--three-snapshots` to verify the repeated request sequence or
`--disconnect-after-first` to verify the failure boundary.

The separate `discovery_observe_trial` executable performs scoped discovery,
two matching settings observations and one in-memory snapshot decode in the
same task-owned session. It uses the experimental TLS provider and does not
authorize setup or publish a recording. Its independent disposable fixture is:

```text
python3 experiments/unifi_https_snapshot_lab/discovery_observe_fixture.py BIN CERT_DER CERT_PEM KEY_PEM JPEG_FIXTURE
```

The fixture checks the request order, invalid image, changed settings,
discovery mismatch and certificate mismatch. See the
[UniFi reference notes](../../docs/UNIFI_DIRECT_REFERENCE.md) for the
physical-camera result and qualification limits.

An experimental `--serializer-inspect` flag may be placed immediately before
`--owner-authorized` (after `--three-snapshots`, if used). It requests the
separately authorized serializer-retention operation, temporarily holds the
three selected JSON values in memory, rechecks disclosure authority and prints
only destination-representation and `withOpus` categories. It does not print
destination addresses or serializer parameters. The values are not exact
source bytes, a durable recovery record, or a verified restoration command.
The owner-authorized scope must specifically include this in-memory inspection.
The revised lab passed three independent TLS fixture cases and one bounded,
read-only G4 session; see the direct-UniFi reference for the evidence and
remaining trust and recovery limitations.

For an explicitly authorized repeat comparison, place `--repeat-serializers`
before `--serializer-inspect`. The lab reads settings twice within the same
camera session and prints only whether their serializer bindings match; it does
not print the binding values. The scope must allow both settings reads. The
fixture's `--repeat-settings` and `--changed-settings` modes independently
exercise equal and changed comparisons. A matching pair is not proof of
long-term camera stability or a restoration command.

## Task-owned HTTP integration (2026-11-05)

The lab now imports the actual `camera_http` owner and wraps its existing
Asupersync-metered TLS client with an experimental async TLS adapter. The
independent Python TLS fixture passed login, status, a 60,000-byte settings
response, snapshot, Rust JPEG decoding and exact private fixture output. The
first integrated fixture failed before sending its login request because its
policy advanced the canonical task clock before the HTTP owner admitted an
older sample; moving the owner's sample after policy revalidation fixed that
regression. A clock-revalidating task-owned loopback test covers the case.

On `trj`, the same corrected executable rejected both a changed certificate and
a different valid key before accessing a nonexistent credential path. It then
logged into the owner's G4 and received HTTP 200 for status, settings and a
snapshot; the FSS decoder reconstructed one 640×360 luma frame. The output
remained in memory and the task returned a completed receipt. This created a
new camera session with unknown expiry. The executable SHA-256 was
`e07d89009d81231ca0eb81e26ef00fb839db9ea1e464e3ecca2fd07689ce809e`;
the imported HTTP owner source SHA-256 was
`2bdd3fd8b0892f2999fa99d6d3d40151b4138b3f2e9729afc41cf5d361134d14`.
The certificate was observed on the same LAN, not independently authenticated.
The TLS adapter and cryptographic provider remain experimental, the lab lease
revalidates its private file synchronously, and this does not establish native
continuous recording, automatic setup, physical device identity or camera
session continuity.

## Repeated direct snapshots (2026-11-06)

With one task-owned HTTPS connection and one camera login, the optional
three-snapshot mode received and decoded three 640×360 luma images from the
owner's G4. Both adjacent JPEG digests changed. The mode stores no image by
default, and this run did not request output. It created a login session with
unknown expiry; the certificate had been observed on the same network and
does not independently prove physical device identity. No camera settings
were changed. Immediately afterward the recorder service and bulk fallback,
upload and discovery timers were active; their active state alone does not prove
uninterrupted recording or retention.

Independent loopback TLS fixtures on the build worker and on `trj` verified
three sequential requests and JPEG decodes, and a deliberately disconnected
sequence failed without reporting or writing a complete output. The default
single-image fixture also passed on the build worker. The tested Linux
executable, after debug-symbol stripping, had SHA-256
`6be3d97c92ff63d75b702fc6c901f73957c8312291eedc028d8266333517eb51`;
the lab `main.rs` SHA-256 was
`5ceea221b6a279789f3ffe2a8217b0eb159803a02e1a7c1a9687cd8bd9bc6fd5`,
and the imported `camera_http.rs` SHA-256 was
`bf8e8dff25b4cf6840b17a25769081524161c15b26f722c59de24908aeec317e`.
Strict-remote build job `30098575685845009` initially failed artifact delivery;
same-job recovery completed delivery and acknowledged source release. The
isolated build used matching core, runtime, codec and camera source, with a
reduced laboratory manifest. These observations establish repeated still
reads, not native video, camera adoption, automatic setup or a recorder.
The separate source-matched camera HTTP contract passed 1/1 test with three
consecutive snapshot requests and its existing interruption/refusal controls
in strict-remote job `30098575685845010`; the terminal result was acknowledged
and its source released. That isolated contract build used a reduced manifest.

## Temporary controller handoff trial (2026-11-05)

`src/bin/handoff_trial.rs` is an isolated Rust laboratory command for one
explicitly authorized camera and controller destination. It verifies the
caller-supplied TLS certificate pin before opening the credential file, checks
the observed controller twice, journals an effect before dispatching a single
settings request, and checks the reported address afterward. A readback is a
camera claim rather than proof of adoption. An indeterminate write must be
reconciled; this tool does not retry it. The parent of a new journal must be
private. The pinned certificate used for the G4 was observed on the same LAN,
not independently authenticated. Its TLS provider, synchronous journal and
credential handling are laboratory components, not a production trust design.

The optional `--observe-only` flag, after `--owner-authorized`, reads settings
twice and exits before creating a journal or sending a settings update. It
classifies stable claims as expected, destination, different, unset, missing or
unsupported, and refuses a changing claim. The existing arguments and private
journal-parent requirement still apply; the journal path itself is not created.
On `vmi1153651`, fourteen independent TLS fixture cases passed, including four
read-only cases that checked request order and absence of a PUT or journal.
The tested executable SHA-256 was
`bbb5499ab306d567b5c09d52538ca6d1b06e9b5fdd725b7e0a8031fae8bd7602`.
On the owner's G4, the same executable reported a stable expected-controller
claim with no effect and a completed task receipt; the journal path remained
absent. This created a login session of unknown expiry. The reported address is
not authenticated device identity and does not settle any previous handoff.

The final binary passed five independent synthetic HTTPS fixture cases on
`ts1`: forward, restoration, already-destination no-op, stale-controller
refusal, and pin mismatch before credential access. A preliminary binary passed
the same fixture and confirmed the real G4's existing controller without a
settings write. During the subsequent owner-authorized G4 trial, the forward
handoff readback did not match the requested destination; a native controller
connection ended with unexpected EOF and no clip. The existing address was
observed again, an independently scheduled restoration check reported an
already-destination no-op, and the existing recorder verified and uploaded
fresh segments afterward. This does not establish a successful native takeover,
recording continuity during the trial, or complete automatic enrollment.
In a second protected physical trial using the final fixture-tested handoff
binary, the handoff readback again failed to confirm the destination. The
camera reached the diagnostic Rust controller over TCP, but its experimental
TLS handshake ended in EOF. The existing controller address was later observed
again, and the independently scheduled restoration check completed as a no-op.

In a later isolated attempt with the dedicated existing controller temporarily
stopped under independent recovery timers, the handoff readback again did not
confirm the destination and the native listener saw no camera connection. The
existing controller restarted, but the camera required a reboot to reconnect,
causing a recording gap. A new segment was subsequently verified and uploaded
by the existing recorder. The handoff journal remains subject to reconciliation.

The laboratory handoff diagnostic now reports the payload-free readback
classification when the requested address is not reported, while retaining the
unresolved effect and refusing automatic replay. Seven independent synthetic
HTTPS fixture cases passed on `hz4`, including previous-address and
different-address readbacks. An initial fixture run with an RSA certificate
failed the experimental TLS handshake; the seven cases passed with a P-256
fixture certificate. This does not classify any earlier physical readback or
establish the cause of its failure.
In a subsequent physical G4 handoff with this diagnostic, the immediate
readback was `Previous`; the separately running native listener saw no camera
connection before its deadline. A no-change observation then confirmed the
existing controller address. The readback does not distinguish a change that
was never applied from one subsequently reversed by another controller; the
journaled effect remains subject to reconciliation. The separate restoration
check found the existing address and made no write. The recovery watchdog
abstained without creating a reboot marker, and fresh recorder segments were
verified and uploaded after the attempt.

The handoff laboratory now prints only the bounded shape of the HTTP response
and samples three controller readbacks across roughly two seconds after one
write. It reports an unstable or unconfirmed sequence as unresolved and does
not retry the change. Nine independent HTTPS fixture cases passed on `hz4`,
including a delayed change, a reversal, and a canary proving the synthetic
response's private field was not printed. The elapsed times are minimum
intervals, since each request takes time. Neither a successful HTTP response nor a requested
readback establishes authenticated adoption or settles the effect.

The physical G4 was later tested with that timeline. Its HTTP response was
200 with an empty body and all three readbacks reported the previous address;
the native listener received no connection. This does not prove whether the
write was ignored or immediately reversed, and the journaled effect remains
subject to reconciliation.

## Temporary existing-recorder recovery watchdog

`recovery_watchdog.py` is a one-shot operational safeguard for this laboratory
trial and the existing transitional recorder, not a native FSS component. It
abstains unless the recorder log contains two consecutive camera-offline startup
failures in the bounded trial window, the observed camera certificate matches
the private pin, the camera reports the original controller, and the recorder
still reports that failure immediately before recovery. Only then does it create
and sync a private exclusive marker before sending at most one reboot request.
An indeterminate request must not be automatically retried. The LAN-observed
certificate pin is not independent device identity, and these checks do not
establish continuous recording during a handoff.

Six unit tests cover recorder-state classification, abstention, pin checks,
marker reuse and revalidation. Six additional loopback TLS cases passed on the
Mac and `trj` with a synthetic camera and real private files: pin mismatch,
different controller, recovered recorder, marker-before-reboot, existing
marker, and a dropped reboot response. The loopback fixture controls recorder
status and does not qualify systemd, live journal access or actual recovery.
A real systemd preflight on the recorder host
abstained without contacting the camera or creating a marker while the recorder
was healthy. In the later protected G4 trial it again abstained on recorder
state and created no marker; the independent restoration check observed the
existing controller address and made no change. The recorder subsequently
verified and uploaded fresh segments. This watchdog is specific to the current
transitional service and does not implement automatic camera enrollment or a
production recovery service.
