# Scoped TLS server entropy research

This isolated experiment explores a possible path to task-owned entropy for
the direct UniFi TLS server. It is **not production TLS** and is not an
admitted dependency or provider. Its separately invoked TLS-only probe has
been exercised against the owner's G4, as documented below. It changes a disposable
copy of rustls 0.23.46, not the workspace's pinned dependencies.

The patches add optional per-configuration client and server randomness and
key-exchange hooks that receive the same respective sources. The experiment's
configurations are made per connection and admit TLS 1.3 only. The deterministic API fixture uses predictable bytes; the Linux task-owned
fixture uses operating-system entropy. Both use a test-only X25519 adapter,
`rustls-pure` 0.15.4, and disposable TLS identities. Predictable fixture bytes
and the experimental provider must never be used for real camera sessions. The patch permits ordinary ambient provider
behavior when both optional fields are absent; the tests deliberately install
panic-on-use fallback hooks only on the scoped server path.

The selected lab handshake consumed 64 bytes from each of two separate sources,
and refused exhaustion both before and during key exchange, a revoked source,
an incomplete hook pair and an invalid low-order peer. An independent OpenSSL
client verified a disposable CA and exchanged TLS 1.3 application data with the
scoped server. This is a small synthetic interop/fault sample, not a full audit
or G4 evidence.
The client side uses an ordinary provider, so the experiment does not prove the
entire process has no ambient entropy. The patch by itself permits configurations
to be shared; the Linux `owned::Session` experiment instead consumes a configuration
and installs a fresh entropy lease for each session.

The Linux experiment obtains bounded bytes from a verified `/dev/urandom` device
under an FSS task's `AdapterAuth` grant and byte budget. It checks the task and
runtime context around handshake and I/O polls and fences stopped sessions. On a
metered loopback transport, a TLS exchange passed with panic-on-use server fallback
randomness and key-exchange hooks, and a task lacking `AdapterAuth` was refused.
The fleet adapter compiles against the existing routed acceptor and rejects duplicate
resources, undersized entropy leases and enabled TLS tickets. Two Linux task-owned
loopback tests passed in strict-remote job `30106308287922181`. In a separate
synthetic two-camera scenario, job `30106308287922186` passed one routed TLS and
WebSocket upgrade while another handshake was stalled, and checked the capacity
limit. The trimmed fixture is included in this harness. These are not
physical-camera tests.

A separate client-side API experiment supplies random bytes and X25519 key
exchange per configuration. It refuses incomplete hooks, TLS 1.2, ECH, early
data and QUIC in scoped mode. Four synthetic client tests cover two independent
sources, exhaustion, incomplete scope, low-order peers, an unsupported
HelloRetryRequest group, and an exchange with an independently verified OpenSSL
server. Four existing server-scope tests also passed with the combined patch in
strict-remote job `30106308287922185`. In these client tests the bytes are
predictable fixtures; they do not establish full provider entropy closure. A
separate Linux client session now uses task-authorized `/dev/urandom` bytes,
disables resumption, and passed two metered loopback tests: a successful
exchange and refusal without `AdapterAuth`. Together with the two server
loopback tests and the fleet fixture, this passed in strict-remote job
`30106308287922187` (5/5). The certificate and clock authority, provider and
all cryptographic dependency paths require separate qualification. Both scoped
configurations report non-FIPS status.

A later fixture uses the task-bound, explicitly pinned client for synthetic
camera setup and the task-bound fleet server for the routed controller connection.
Strict-remote job `30106308287922189` passed that scenario and the four separate
client/server authority tests (5/5). The pinned adapter compares the supplied
DER certificate and verifies the handshake signature; it does not verify a
certificate chain, hostname, or validity dates, and the pin's origin is not
independently established by the adapter. Strict-remote `ts1` job
`30106308287922190` passed two synthetic pin tests: a correct pin exchanged
application data, and a wrong pin stopped before plaintext. No real camera was
contacted.

The entropy lease uses bounded atomic byte slots: consumed bytes are cleared,
close and cancellation fence further fills and clear the lease, and an
exhaustion failure clears unused bytes. The previous lock-based close retained
bytes when the lock was busy; a targeted regression demonstrated that failure.
The revised lease passed five focused cancellation, exhaustion, concurrent fill,
and close tests, together with the fifteen existing synthetic TLS and fleet
tests, in strict-remote job `30106308287922197` (20/20). The concurrent test
allows an overlapping fill to finish before close takes effect; it does not
establish arbitrary scheduling or power-loss behavior.

The lab also provides an explicitly owned blocking-pool acquisition. It checks
and debits task authority before admission, refuses a missing pool instead of
running inline, waits for worker release, and rechecks task authority before
returning a one-use lease. Client and server sessions can consume these leases.
The caller must retain and join the acquisition, including after abort; dropping
it cannot synchronously drain an already-running system call. Job
`30106308287922198` passed 26/26 synthetic tests, including offloaded client
and server exchanges, missing-authority and missing-pool refusal, and a test
that holds a worker open after cancellation to verify that join waits for release.
A lease-consuming fleet adapter and pinned-camera connection path now use
pre-acquired leases without reading entropy on the async thread. A synthetic
fleet test passed with these paths, including duplicate and unrelated lease
refusals and an exact clock-mapping mismatch check, in job `30106308287922200`
(27/27). The older synchronous entry points remain; automatic lease replenishment
is not wired into a service.

The experimental fleet transport also has a bounded `LeaseSupply` owner. When
polled, it acquires leases for empty slots and replenishes a slot after use;
it limits concurrent workers, latches failures until explicitly rearmed, and
requires stop followed by polling through `Stopped` to drain admitted work.
Strict-remote `ts1` job `30106308287922206` passed 27/27 synthetic tests,
including two-camera replenishment and shutdown immediately after admitting a
worker. The separate cancellation test holds a started worker open and checks
that its acquisition cannot be joined before release. At that stage the supply
inventory was fixed. The caller must actually poll and drain it, and dropping it cannot
synchronously drain running work. This is a laboratory component, not an
unattended service or automatic enrollment of detected cameras.

`LeaseSupply::next_with_pump` now drives the existing discovery/route pump and
lease supply together, using the pump's alternating polling. It refuses a
pump whose acceptor holds a different transport and retains both owners if a
borrowing wait is dropped. Strict-remote `ts1` job `30106308287922209` passed
27/27 synthetic tests, including scanning and lease replenishment during a
stalled handshake, mismatched-supply refusal, dropped-wait preservation, and
shutdown. That version of the scenario preloaded initial leases.

The transport now retains a routed handshake while its lease slot is empty,
registers one bounded waiter per resource, and wakes it after an authorized
lease is installed. Cancellation or deadline drops the route and removes the
wait registration; an already-active competitor is refused. A stale registration
left by reentrant drop cannot block its successor. The prior implementation
failed the new reconnect regression in `ts1` job `30106308287922210`; the
revised implementation passed 29/29 synthetic tests in job
`30106308287922214`. The loopback fixture consumes a lease, reconnects before
replenishment, completes that same connection after replenishment, and checks
that shutdown closes a different waiting socket. The test is not a production
service, a physical camera test, or proof of every scheduling interleaving.
Callers must still poll and drain the supply; automatic enrollment, production
TLS admission and actual camera handoff remain open.

The laboratory fleet transport now supports an append-only, 128-slot resource
inventory with stable addresses. Its caller can synchronize resource names from
an existing owner-supplied fleet without stopping in-flight connections. It
rejects a mismatched prefix before publication, wakes the waiting supply when
names are appended, and supports starting with zero resources. The fixture also
appended an owner-supplied enrollment while the pump held an active handshake;
that enrollment was not observed in its discovery window. Strict-remote `ts1`
job `30106308287922218` passed 30/30 synthetic tests. That version required
caller-invoked synchronization.

The combined pump now synchronizes from its acceptor's exact fleet and waits for
later owner-supplied enrollments. In job `30106308287922227`, 30/30 synthetic
tests passed; a simulated camera was discovered and later explicitly enrolled
while the loop was parked, waking it to provision the matching lease while an
existing handshake stayed active. Independent reference-crate job
`30106308287922226` passed one focused notification test, including two waiters,
duplicate refusal, and interruption when polled with a cancelled task context.
Discovery claims do not create enrollment, credentials or authority. The tests
do not establish automatic camera setup, a production service, physical-device
identity or handoff, or cancellation behavior for every runtime schedule.

The combined loop can now also drive a caller-owned `CameraWorkSet`, returning
each completed camera operation to the caller while alternating preference
with fleet progress. The loop checks the supply/acceptor binding before polling
camera work. In strict-remote `ts1` job `30106308287922231`, 30/30 synthetic
tests passed. A discovered, explicitly enrolled third simulated camera went
through the existing pinned HTTPS setup owner and then a TLS/WebSocket controller
route. Its login reply was held until a second simulated camera completed a
controller connection, while a first handshake remained stalled. The fixture
retained the setup trace and exercised a dropped borrowing wait and a mismatched
supply. The caller still creates the setup work, resolves credentials, handles
its outcome and effect trace, and drains outstanding work. The tests do not
settle a physical effect or establish unattended camera setup or recording.

The lab adds an `AutomaticWork` owner that selects a ready, explicitly enrolled
fleet entry and asks a caller-supplied factory for its authorized setup future.
It binds to the exact fleet and transport, bounds concurrent work, latches
attempts for the lifetime of that owner, and returns factory failures without
silently retrying. Stopping admission preserves pending futures for explicit
retirement. The factory's promise not to perform synchronous effects is a
caller contract, not a type-enforced guarantee.

Strict-remote `ts1` job `30106308287922242` passed 30/30 synthetic tests. The
selector was already waiting when a discovered simulated camera was explicitly
enrolled; it woke and admitted work. A separate factory-provided setup future
then completed the existing HTTPS setup and controller route while another
camera progressed. The test also covered mismatched fleet and transport,
stopped admission, pending-work retention and a latched factory refusal. The
attempt latch is in memory only; caller-supplied credentials, restart recovery,
safe retries, physical-camera handoff and production TLS remain open.

The new `camera_setup::run` future constructs the pinned, task-metered camera
connection and invokes the existing tracked setup owner. Before connecting it
checks the enrolled certificate digest against the supplied DER, the credential
handle, discovery source, resource, one-use lease, listener address, and caller
admission and login authority. It borrows the effect trace from the caller, so
an interrupted future does not own that trace. The caller still resolves the
credential bytes and independently provisions the certificate and identity.

Strict-remote `ts1` job `30106308287922248` passed 30/30 synthetic tests. The
fleet fixture completed setup and a controller route for an explicitly enrolled
simulated camera. Six refusal cases checked a valid wrong certificate, wrong
credential handle, wrong discovery address, wrong resource, denied login and
denied admission before either probe socket accepted a connection. The test does
not prove that the credential bytes correspond to the handle, establish an
independent physical identity, or qualify the TLS provider or a real handoff.

This remains research: legacy adapter entry points still read operating-system
entropy synchronously, a task grant can change inside a poll, and a write interrupted after polling can be
indeterminate. The test does not audit every provider entropy path or cipher suite,
test cancellation races, validate a real camera identity, or establish safe session
recovery. `rustls-pure` remains unadmitted. Production requires dependency and
provider review, a supervised entropy boundary, independent identity and effect
reconciliation, and resolution of the prior indeterminate camera handoff.

## Prepare an isolated test workspace

`prepare.py` accepts a **new absolute directory outside the project checkout**
and a locally cached `rustls-0.23.46.crate`. It verifies SHA-256
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`, extracts
only regular files/directories into the new workspace, applies the patch, and
uses OpenSSL to generate a disposable CA and test-only private key there. It
does not modify the Cargo registry or invoke Cargo. Do not commit those generated
fixtures or use them outside this experiment.

```sh
python3 experiments/unifi_tls_scoped_entropy_lab/prepare.py \
  /absolute/path/to/new-lab-directory \
  /absolute/path/to/rustls-0.23.46.crate
```

Run the isolated workspace's `cargo test --locked -j 1 --test scoped_entropy`
`cargo test --locked -j 1 --test client_scoped_entropy`, and, on Linux,
`cargo test --locked -j 1 --lib --test owned_entropy --test owned_client --test fleet_route --test pinned_client`
on a controlled build worker with OpenSSL, `timeout`, `ip`, and a locally assigned
private IPv4 address. The fleet fixture selects an address assigned to the worker;
its simulated cameras use loopback addresses and disposable credentials. The fixtures
expire after two days. The standalone lockfile is for this experiment and is
not the FSS workspace dependency closure. The rustls source is distributed
under its upstream Apache-2.0/ISC/MIT license choices; the upstream package
contains its license texts.

### Scheduled setup with retained entropy acquisition (2026-11-12 UTC)

The experimental `camera_setup::run_with_acquisition` joins a caller-started,
task-and-resource-bound entropy acquisition inside a scheduled camera setup
future, then transfers the resulting lease to the existing certificate-bound
setup. The caller retains the acquisition and effect trace. After cancellation,
it can inspect `is_drained()` and must abort and join an undrained owner. The
network wait does not bound entropy acquisition; the caller must impose its
own deadline and perform that drain. No worker is spawned by this future.

Strict-remote `ts1` job `30106308287922251` passed 30/30 synthetic tests
(11+4+1+4+4+2+4). Its fleet fixture refused a wrong resource binding without
opening the probe socket, then aborted and drained that retained acquisition;
it also completed a simulated enrolled camera setup with acquisition inside
the automatic work future, and checked the terminal drained state. The job
finished with terminal acknowledgement and source/pair release. The overlay
fingerprint was `13deddb09463ea440e2fa5a448782c9c2ed464b06f166e3a1fbfb2013b2c9941`.

The caller still starts and bounds acquisition, supplies credentials and the
identity/pin, owns admission and effect reconciliation, and handles all
outcomes. This does not establish a credential-to-handle mapping, unattended
enrollment, provider admission, physical identity, real-camera handoff, native
recording, or retention. The prior physical handoff and time-sync effects remain
indeterminate; no camera effect was attempted in this synthetic test.

### Scoped P-256 client and live TLS-only observation (2026-11-12 UTC)

The experimental client now implements task-scoped P-256 ECDH as well as
X25519. It obtains a fixed-width scalar from the existing per-connection entropy
source, bounds rejection sampling, emits an uncompressed SEC1 point and refuses
invalid peer points. The camera TLS configuration permits one explicitly
selected group; it does not automatically discover group compatibility. The
new direct `p256` dependency is confined to this non-production laboratory.

The first TLS-only G4 probe, configured for X25519, failed its handshake. An
independent OpenSSL check also failed with only X25519, while P-256 succeeded
and the observed certificate matched the previously retained network pin.
After the scoped P-256 change, a TLS-only probe from ts1 to the observed G4
completed TLS 1.3 with that pin and verified the server handshake signature.
It sent no HTTP request or credentials and made no settings change. The same
probe's independent disposable P-256 server fixture passed matching-pin and
wrong-pin cases, observing zero application bytes. The first fixture version
returned a server-side BrokenPipe while it attempted to issue TLS tickets; the
reported fixture result uses a no-ticket server and successful completed runs.

Strict-remote ts1 test job `30106308287922255` passed 33/33 tests
(12+4+1+4+4+4+4), including P-256 agreement, malformed-point and invalid
scalar refusals and pinned-client success and wrong-pin refusal. It exited
zero, was acknowledged and released source and pair. Its source overlay
fingerprint was `e8a719bdae713628684f4c633d81b0e121a7b07cea731a10aa662f95757bd087`.
Build job `30106308287922256` completed remotely with exit zero; its wrapper
returned 102 because RCH rejected installing a Linux binary on macOS. Its
terminal result was acknowledged and source and pair were released. The Linux
probe used for fixture and G4 checks had SHA-256
`dc7a0f12aa48b6fc4a124aac0998e50ebe4d33e90ca730dd527051003c29aadb`,
matched before and after the live check. The observed network certificate
digest was `f266d3f9dbede6c30bc062c2d06d0b8091431d8347e5c6898de5ed09832bae36`.
The recorder and both relevant timers were active with NRestarts=0 afterward.

This is an actual-camera TLS handshake, not a login, video stream, physical
identity authentication, production TLS admission, automatic setup or a
recording. The pin was collected on the same network. No prior camera effect
was retried or reconciled; the original trial sources used ordinary journals
without the later independent pin-retention mechanism. No pin store was found
in the retained original trial directories. The old handoff and time-sync
outcomes remain indeterminate. The repository fleet gate also reported stale
ARP data and unrelated launchd/plist findings during this investigation; it
was not changed or treated as a UniFi qualification pass.

### Live read-only snapshot with task-scoped P-256 TLS (2026-11-12 UTC)

The experimental `live_snapshot_probe` composes the task-bound P-256 TLS
client, the existing camera HTTP owner, and the first-party MJPEG luma
decoder. It permits only login, status and one snapshot; it loads the existing
private credential file only after the certificate pin and TLS handshake
signature have succeeded. It decodes in memory and does not deliberately save
the image or print credentials. The private-file lease code is a copy of the
previous snapshot laboratory's implementation, not a general secret backend.
Its file inspection and JPEG decoding remain synchronous, authority depends
on caller claims, and library/OS copies are not fully zeroized.

A disposable P-256 TLS fixture passed three process cases using synthetic
credentials and a synthetic 16x16 JPEG: matching pin with the exact
login/status/snapshot sequence, a wrong pin with a nonexistent credential
path, and a truncated image response. It checked no synthetic credentials
were printed. An initial fixture attempt failed due to a Python bytearray
type error; the corrected fixture passed all three. The fixture, JPEG and
stripped probe SHA-256 values were respectively
`826d3828edfa333eb33ba427bdeba590d8d277d58707c3b3dd193b420fd6fb25`,
`d9470ede0234592f82ef448f1a3f01d0691b1528ad000aad8011fa9e9685b448` and
`6c39177d59e6b7666bf555b1f922d2263c0b9e61c7447706f3fc6b46e835e02a`.

That SHA-matched stripped executable then ran once on trj against the
owner's observed G4 endpoint and network-observed pin. It reported successful
TLS, login and status and decoded one 640x360 JPEG in memory, with no image
output and no management operation. The login may create a camera session
whose expiry was not established. The pin does not independently authenticate
physical device identity. The prior indeterminate handoff and clock effects
were neither retried nor reconciled. The recorder and two relevant timers were
active with NRestarts=0 afterward; this does not establish gap-free coverage.

Strict-remote ts1 job `30106308287922260` completed its selected tests with
exit zero, terminal acknowledgement and source/pair release, using overlay
`a5f7b1b5d465e37d61e3440b9c24d68a5101f101e6d7598dc93952b57f6f8d27`.
The output display truncated one test result, so the exact test binary was
run again on ts1 and its one credential-rotation/permissions test passed.
The retained visible results cover 33 other selected synthetic tests. The
Linux probe build job `30106308287922259` exited zero remotely but returned
102 from its macOS wrapper because it refused foreign artifact installation;
it was acknowledged and source/pair released. The independent process fixture
ran separately via SSH on ts1, not as part of that Cargo test job.

This is real read-only still-image access via the newer experimental transport,
not a live Rust video stream, autonomous enrollment, production provider
admission, direct controller ownership, continuous recording, or 30-day
retention. The G4's higher-resolution stream remains a separate path.

### Scoped P-256 controller-side TLS (2026-11-12 UTC)

The experimental task-owned controller TLS server now supports P-256 as well
as X25519, using the same scoped key-exchange implementation as the client.
It rejects malformed P-256 points before consuming server entropy; the
successful exchange uses the task-owned one-use entropy pool. The caller
still selects the server's supported group configuration. No claim is made
about which groups the G4 offers when it acts as a TLS client.

Strict-remote ts1 job `30106308287922266` passed the selected Cargo test run
and exited zero with terminal acknowledgement and source/pair release. Its
overlay fingerprint was
`5deadd01091dd50a577bdaddb4c4912e1d72f2fd82653faa6ea3ab874ce83ce3`.
The displayed output was truncated, so two retained test binaries were run
again separately on ts1 using the same disposable test identity: the
controller transport passed 7/7 tests, including a Python/OpenSSL P-256-only
client verifying the test CA and hostname with its normal strict policy; the
fleet route passed 1/1, exercising the P-256 configuration in its two-camera
case. The binary SHA-256 values recorded after these reruns were
`94279051f5c7b23085199a0675939adfb0aa8676c896694e70eb0c2cc352e12b`
and `63a8362bd59bc389250f432f3256399d892bb6797ea32f508f82cdb91f72205f`.

An earlier selected run, job `30106308287922264`, failed one independent
peer test because the generated disposable leaf certificate lacked an
authority-key identifier. The test certificate generator was corrected to
include that identifier and an appropriate CA key usage; independent strict
OpenSSL verification succeeded before the passing rerun. That earlier job
exited 101 and was acknowledged with source/pair release.

These are synthetic TLS and routed-controller tests, not evidence that the
physical camera supports this exact inbound negotiation or that an earlier
G4 handshake failed for this reason. No camera handoff or settings change
was performed; prior indeterminate effects remain unresolved. The existing
recorder and its two relevant timers were active with NRestarts=0 after the
test. TLS provider admission, physical identity, direct native video and
continuous recording remain open.

### P-256 fleet setup through synthetic video decode (2026-11-12 UTC)

The scoped TLS fleet integration test now continues past the routed
WebSocket upgrade. For its explicitly enrolled third simulated camera, the
two-capacity case uses P-256 camera and controller TLS, drives the existing
journaled hello, parameter agreement and stream-start conversation, accepts
the simulated camera's TCP video push, and feeds bounded synthetic H.264/FLV
through the existing pipeline, MP4 demuxer and first-party H.264 decoder.
The test requires at least one decoded frame. Other simulated work and a
stalled handshake are retained during earlier portions of the scenario; the
media path itself does not prove unattended parallel recording or durable
source publication. The fixture uses its own fake credentials, synthetic
media and test-only authority, and retains no physical camera data.

Strict-remote ts1 job `30106308287922272` passed the selected fleet test
(1/1), exited zero, was acknowledged, and released source and pair. Its
overlay fingerprint was
`c87c754f6f197ace8d45d782a5ebd5cd751a5b299cefa6d503a303e2bbd4f403`.
The preceding job `30106308287922270` failed with `Conversation(Effect)`
because the synthetic task had not been granted the stream-setting
capabilities; those fixture grants were added before the passing run. The
failed job exited 101 and was acknowledged with source/pair release. The
fleet test, synthetic stream helper and synthetic H.264 source SHA-256 values
were `264968697524f08bc345fcdcc1ee99de613fca736ae907c0593f905bb06a89f2`,
`8059ba5c5763655ab26290f674020e13860b31bafa97a6ef73f8b28381fccc5a`,
and `2a3e84de3a938a60ad254a69fa2fa7f38ada910cad72447b807f3d6266796d32`.
A fresh workspace created by `prepare.py` has matching test source and
passes locked offline Cargo metadata resolution.

This is a synthetic composition test, not a production fleet supervisor,
real-camera TLS inbound qualification, live physical video, independent
identity or 30-day retention. It does not resolve or replay prior
indeterminate G4 effects. The existing trj recorder and its two relevant
timers were active with NRestarts=0 at the post-test check.

### Cooperative fleet setup and active-stream work (2026-11-12 UTC)

The experimental `LeaseSupply::next_with_setup_and_streams` drives the
existing automatic setup selector and a caller-owned active-stream work set
with discovery, controller routing and entropy supply. It validates the
transport and fleet binding before polling either work set, alternates
preference between completed stream and other events, and preserves both
sets when its borrowing wait is dropped. The caller still binds stream index,
session, authority and effect trace, prevents overlapping operations for the
same camera, handles completions, and drains or retires pending work. A
synchronous journal call, decoder or other blocking future poll can stall
the whole loop despite its cooperative scheduling.

Strict-remote ts1 job `30106308287922277` passed 38/38 selected synthetic
tests (13+1+4+1+4+7+4+4), exited zero, was acknowledged and released
source and pair. Its overlay fingerprint was
`779a0d798a16985550800c87f730e518c9df2a219cf0f356edf75b41d8d3386d`.
The fleet fixture checked refusal of an unrelated fleet or supply before a
stream future was polled, a ready stream and admitted synthetic setup, and
retention after a dropped wait. In a separate phase it held the third
simulated camera's P-256 stream-start reply until a second simulated camera
completed a controller upgrade; the first then pushed H.264 that Rust
demuxed and decoded. Automatic setup admission was stopped during that
stream phase; the test does not prove a real concurrent setup and media
stream, long-running service, or physical camera behavior. A comment
clarifying blocking-poll limitations was added after the passing run.

This does not qualify production TLS, automatic identity enrollment, direct
G4 video, effect reconciliation, native continuous recording or 30-day
retention. No real camera setting was changed. The existing recorder and
its two relevant timers remained active with NRestarts=0 at the later check.

### Camera-index exclusion for combined setup and streams (2026-11-12 UTC)

The experimental combined loop now takes a fleet-bound `ActiveStreams`
owner that retains a bounded stream future per enrolled index. It excludes
occupied indices from automatic setup selection, tracks setup futures while
they are in flight, and refuses an existing same-index setup/stream overlap
before polling either set. A refusal retains both owners and their futures.
A setup completion clears the in-flight marker; it does not establish that
the resulting effect has been reconciled. Unknown enrollment and duplicate
stream insertions return the supplied future.

Strict-remote ts1 job `30106308287922282` passed 38/38 selected synthetic
tests (13+1+4+1+4+7+4+4), exited zero, was acknowledged and released
source and pair. Its clean-overlay fingerprint was
`4cf456e3207ee1ea11d4f1d0d3002d8703b3a6d04a9069d4e677477a8e1b9843`.
The fleet fixture covered an occupied camera blocking setup selection,
resumption after stream completion, refusal of an already-running overlap
without polling the stream, post-setup stream admission, unknown/duplicate
stream refusal, mismatched fleet/transport, and the earlier concurrent
synthetic controller/video scenario.

This exclusion is scoped to the exact owners passed to the combined loop;
separately created work owners or the standalone setup API can still overlap.
A caller must bind each future to the correct session and identity, retain
and reconcile effects, and ensure poll operations do not block. This is not
a production supervisor or physical-camera test. Prior uncertain G4 effects
were not retried. The existing recorder and two relevant timers remained
active with NRestarts=0 at the later check.


### Synthetic full-resolution fleet route and passive reconnect watch (2026-11-12 UTC)

The fleet-route laboratory fixture now runs a small `video2` case and a
synthetic 2688 x 1512 `video1` case at handshake capacity two, plus a small
capacity-one case. The simulated camera validates the requested channel in the
management message. In the full-resolution case it sends synthetic H.264
through the media pipeline; Rust demuxes fragments and decodes pictures,
asserting that every decoded picture is 2688 x 1512 and at least one was
decoded. A second camera upgrades while the third camera's stream-start reply
is held. Automatic setup admission is stopped during this stream phase; this
does not prove concurrent setup and streaming.

Strict-remote ts1 job `30106308287922290` passed the single fleet-route test
(1/1, comprising three scenarios), with overlay fingerprint
`16a666acca120d92fac7630a98e3668a04b9a75ea8fd079ad3d47bbf04e4bc81`.
The job exited zero, its terminal result was acknowledged, and both source and
pair leases were released. Earlier jobs `30106308287922284` and
`30106308287922288` failed with exit 101 because the fixture requested three
samples when the final fragment contained fewer. It now uses up to the
available sample count and refuses an empty fragment. This was a test-extraction
error, not evidence of a product media defect. A fresh workspace prepared
from the lab inputs passed locked offline metadata resolution; its test
sources and synthetic video fixture matched the original hashes.

A separate 50-second read-only SYN watch for the real G4 connecting to its
existing controller captured no SYN packets; the kernel reported seven packets
received by the filter and none dropped. No client TLS preference can be inferred
from this watch. Neither the watch nor the synthetic tests changed camera
settings. These results do not prove a physical G4 handoff, direct real-camera
full-resolution capture, continuous recording, or 30-day retention. The
earlier indeterminate physical handoff and clock effects were not retried.

### Explicit setup retry admission (2026-11-12 UTC)

Experimental `AutomaticWork::rearm` allows the supervisor to select an
enrollment again after an attempted setup. It refuses unknown or unattempted
indices, an in-flight setup, and a stopped owner; existing active-stream
exclusion still applies on the combined scheduling path. Rearm does not
perform or verify effect reconciliation, grant authority, provide backoff, or
coordinate independent work owners. The caller must resolve the prior outcome
and authorize a retry; it must not rearm an indeterminate effect merely because
a future returned or a factory failed.

Strict-remote ts1 job `30106308287922296` passed the fleet-route test (1/1;
three scenarios), exited zero, was acknowledged and released source and pair.
The overlay fingerprint was
`68d7189a18978e45e457d49b730ffdf3a06efcec190301cc54c610e0f91ba1ec`.
The fixture checked failed factory retry only after explicit rearm, refusal
while in flight or stopped, repeated/unattempted and unknown refusal, and
active-stream exclusion before the rearmed setup starts. A newly prepared lab
workspace matched the modified source hashes and passed locked offline
metadata resolution. This is experimental synthetic evidence, not automatic
reconciliation, unattended recovery, production admission or a real-camera
handoff. No camera effect was attempted; the recorder and its two timers were
active with zero recorder restarts at the post-test check.

The selector rearm now additionally requires the fleet state to be `Ready`.
A completed real setup moves the fleet to `Finished`; resetting the selector
alone cannot retry it. The separate fleet retry mechanism must first prove an
eligible pre-effect failure and rearm the fleet. Strict-remote ts1 job
`30106308287922298` passed the fleet-route test (1/1, three scenarios),
including refusal after a completed synthetic HTTPS setup. It exited zero,
was acknowledged, and released source and pair. Overlay fingerprint:
`9244b2227b15b63b1a43e473586805f0fbee3f87f6e4082ea00a443b1619e70b`.
The fresh lab workspace matched the test and source hashes and passed locked
offline metadata resolution. The bounded retry queue is not yet integrated
with this combined supervisor; these checks do not establish unattended
recovery or physical-camera behavior.

### Coordinated bounded pre-effect retry (2026-11-12 UTC)

The experimental fleet loop now owns a bounded retry queue alongside automatic
setup, active-stream futures, discovery, routing and TLS lease supply. The
queue is required to match the pump's fleet, context and clock before any work
is polled. Setup completions retain their original outputs and operation IDs;
only an exact fleet-confirmed pre-effect failure can schedule a timer. On a
valid timer event, the owner releases its selection latch even if the latest
scan is absent or conflicted; the existing selector still requires a ready
claim and excludes occupied streams. Stopping the setup owner or supply stops
timer polling and retains the queue. The caller still owns traces, operation
creation, credential/identity authority, event handling and shutdown.

Strict-remote ts1 job `30106308287922304` passed the fleet-route test
(1/1, comprising three scenarios), exited zero, was acknowledged and released
source and pair. The lab overlay fingerprint was
`01511ff4b3b92f7e4dc4e7eeae2c299804e2c2b9ac27ee257fe74d6b76563176`;
the disposable dependency commit was
`4fdba7851b7e8b4a5022967cdb28eb6b62c92813` and its changed pump file
matched the project source. The synthetic HTTPS camera rejected login before
any management effect; the exact failed operation was scheduled, a dropped
wait preserved the timer and a separate pending stream, and expiry restored
selection. The subsequent selected synthetic work was a deliberately
ineligible completion, which did not schedule another timer. A queue from a
different fleet was refused before polling the stream. This does not yet test
a second actual HTTPS setup succeeding within the same retry owner, production
supervision, a physical camera, direct live media, or durable retention.

An initial remote request was rejected before admission because the dependency
overlay was specified in the wrong root; it ran no test. A fresh lab workspace
matched the modified lab source and test hashes and passed locked offline
metadata resolution. The real G4 was not modified. Its existing recorder and
both relevant timers were active with zero recorder restarts at the later check.

### Synthetic HTTPS retry through successful setup (2026-11-12 UTC)

The fleet fixture now continues the same retry owner from a synthetic HTTPS
login rejection through the bounded timer and a fresh HTTPS setup operation.
The timer directly releases selection, with no intervening manual latch reset;
the subsequent operation returns an observed setup result and does not
schedule another retry. A separate synthetic stream future remains owned while
setup progresses. In the capacity-two scenarios another synthetic controller
upgrades during setup; afterward the fixture routes and decodes synthetic
video, including the 2688 x 1512 profile case. The factory explicitly supplies
the next future, credentials, trace and fresh operation ID. The test uses
separate fixture effect journals for the failed and successful owners; it does
not prove journal continuity, restart recovery, or a production supervisor.

Strict-remote ts1 job `30106308287922308` passed the fleet-route test (1/1,
three scenarios), exited zero, was acknowledged and released source and pair.
Its lab overlay fingerprint was
`ae826f37d73ca2593a446d8b42c99616d1ce84113a275bd3d2d4551e938ab772`,
with disposable dependency commit `4fdba7851b7e8b4a5022967cdb28eb6b62c92813`.
An earlier attempt, job `30106308287922305`, failed to compile because a
fixture policy's lifetime did not cover the retained work; correcting its
ownership order fixed that error. A freshly prepared lab workspace matched the
test source hash and passed locked offline metadata resolution. The G4 was not
modified. The recorder and both related timers remained active with zero
recorder restarts at the post-test check. This remains synthetic evidence, not
a real-camera retry, direct live capture, uninterrupted recording, or 30-day
retention.

### Synthetic stream during camera setup (2026-11-12 UTC)

In the capacity-two fleet scenarios the synthetic camera setup is now held
at its HTTPS login response until another simulated camera completes
controller TLS/WebSocket negotiation, receives a stream request, sends H.264,
and Rust demuxes and decodes at least one picture. The setup then resumes and
returns an observed result. The concurrent stream is selected as `video1` and
all decoded pictures are checked for 2688 x 1512 in the full-resolution case;
the small case uses `video2`. A separate deliberately pending stream remains
owned. The capacity-one scenario continues to test the handshake-capacity
refusal but does not run the concurrent media phase.

Strict-remote ts1 job `30106308287922313` passed the fleet-route test (1/1,
three scenarios), exited zero, was acknowledged and released source and pair.
The lab overlay fingerprint was
`611716f5ad15c04b44914d7c80b5b10f56c95c1531214620b0af80435edfe06b`
with disposable dependency commit `4fdba7851b7e8b4a5022967cdb28eb6b62c92813`.
Job `30106308287922312` initially failed with `Conversation(Effect)`
because the fixture authorization guard was hard-coded to the other simulated
camera; the corrected guard binds the intended camera MAC. A fresh lab
workspace matched the test source hash and passed locked offline metadata
resolution. These are simulated media and identities, with independent fixture
effect journals and synchronous work inside cooperative polls. They do not
establish an unattended service, nonblocking performance, real-camera setup,
direct live recording or retention. The G4 was not modified; its recorder and
both relevant timers remained active with zero recorder restarts afterward.

### Scoped TLS fleet to managed archive (2026-11-12 UTC)

The scoped-entropy laboratory fleet fixture now carries the third synthetic
camera's received H.264 through the managed video and source archive owners,
rather than stopping at in-memory demux. It reads back the published video,
decodes at least one picture (checking 2688 x 1512 in the high-profile case),
reads original source records and video-linked objects, and verifies exact,
gap-free, non-overlapping coverage of the complete synthetic FLV bytes,
including the retired tail. The controller fixture stays open until the archive
owner retires; a drop guard releases it on early failure. The test also retains
the earlier parallel setup and separate-camera video phase. The caller supplies
all authority, archive configuration, credentials and operation IDs.

Strict-remote ts1 job `30106308287922321` passed the fleet-route test (1/1,
three scenarios), exited zero, was acknowledged and released source and pair.
The lab overlay fingerprint was
`785cd01dd7fd509dbd4bd30634a402e983eab681e156af756dacf8de09f1791c`;
the disposable dependency commit was
`4fdba7851b7e8b4a5022967cdb28eb6b62c92813`. Jobs
`30106308287922316` and `30106308287922317` failed to compile due to
fixture formatting and ownership mistakes, respectively. Jobs
`30106308287922318` and `30106308287922319` failed after the intentionally
stalled handshake hit its original 10-second deadline during the longer
archive scenario. Job `30106308287922320` was rejected by the acceptor at
runtime because a 120-second fixture deadline exceeds its 30-second maximum.
The passing fixture uses that supported 30-second bound; this is not a
production latency guarantee. An earlier request was rejected before admission
for an incorrect dependency path and executed no test.

A fresh workspace prepared from the lab inputs matched the test and support
source hashes and passed locked offline metadata resolution. This is finite
synthetic traffic and temporary storage; it does not prove real-camera direct
video, uninterrupted recording, restart recovery, production TLS admission,
or 30-day retention. No camera effect was attempted. The existing trj recorder
and both related timers were active with zero recorder restarts afterward.

### Bounded preflight connection retry (2026-11-12 UTC)

The experimental camera setup owner now offers bounded, task-checked retry for
selected transient TCP/TLS connection failures before the camera HTTP owner or
fleet setup operation is entered. It accepts at most four caller-owned entropy
acquisitions, uses a bounded fixed delay with cancellation checkpoints, and
keeps the attempt/retry trace outside the borrowing future. A setup error,
authorization refusal, certificate or protocol-handshake rejection, entropy failure,
cancellation, protocol limit or prepared camera effect is not automatically
retried. The caller must abort and join unused or interrupted acquisition
owners, retain both traces, and reconcile any later setup effect. Dropping an
outer supervisor wait preserves the retained setup future; dropping the setup
future itself requires explicit cleanup and is not an automatic resumption.

Strict-remote ts1 job `30106308287922325` passed 14/14 library tests and
1/1 fleet integration test (three scenarios), exited zero, was acknowledged,
and released source and pair. The lab overlay fingerprint was
`6f1264f16e72010836340db60d0bd580096881da8f42a462762150300a4310a7`
with disposable dependency commit `4fdba7851b7e8b4a5022967cdb28eb6b62c92813`.
The synthetic fixture first bound a non-listening socket, observed a real
connection refusal, then listened before the next attempt. It confirmed the
retry reached the synthetic HTTPS camera, that a dropped supervisor wait
retained pending setup, and that denied login authority caused no retry or
connection and left its unused acquisition for explicit abort and join. The
focused classification test refuses handshake, authority, entropy and limit
failures. A fresh workspace matched source/test hashes and passed locked
offline metadata resolution. This is not deployed service behavior, real-camera
retry, provider admission or an effect-reconciliation proof.

A read-only check found the trj fallback service's current archive script uses
a 30-day age rule, 16 matching files had been modified within 15 minutes, and
the recorder and two related timers were active with zero recorder restarts.
This does not prove uninterrupted coverage or 30 days of retained video. No
physical-camera setting was changed.

### Live read-only profiles through scoped TLS (2026-11-12 UTC)

The experimental task-scoped snapshot probe now optionally reads sanitized
camera-reported video profiles before decoding the JPEG. The option permits
only the existing read-only settings operation and reports each numeric field
as reported, missing, or unsupported; it does not expose serializer
destinations or credentials. The default request sequence remains unchanged.

The Linux build ran on ts1 in strict-remote job `30106308287922326`: Cargo
exited zero, while the macOS wrapper returned 102 because it refused to
install a foreign Linux executable. The result was acknowledged and source
and pair were released. The retained Linux executable SHA-256 was
`f761ad981c4ca7fd5ba8156e7e7b752a57c4b625d4a6117631e2b526761e36ec`.
Separately on ts1, an independent synthetic P-256 fixture passed five cases:
default snapshot, wrong pin before credential access, truncated image, normal
profiles, and missing/unsupported fields. Its first run passed the first four
and failed the last because the fixture response had an extra JSON delimiter;
the corrected fixture passed 5/5. This process fixture was not part of the
Cargo build job. A freshly prepared workspace matched the probe and fixture
hashes and passed locked offline metadata resolution.

The SHA-matched binary then ran once on trj against the owner's observed G4
with the previously network-observed certificate pin and private credential
file. It completed TLS, login and status, read the current settings and decoded
a 640 x 360 JPEG in memory without deliberately persisting it. The camera
reported video1 as 2688 x 1512 at 30 fps, video2 as 1280 x 720 at 30 fps,
video3 as 640 x 360 at 15 fps, and the JPEG profile as 640 x 360 at 2 fps.
These are device-reported settings, not proof of full-resolution media
delivery, independently established physical identity or capture time. The
login may create a camera session whose expiry is unknown. No camera setting,
prior indeterminate handoff or time-sync effect was changed or retried.
Afterward the existing recorder and both related timers were active with zero
recorder restarts; 16 matching fallback files had been modified in the prior
15 minutes. This is not proof of uninterrupted recording.

### Bounded selection of reported camera profiles (2026-11-12 UTC)

The shared camera API now selects among three reported video profiles using
caller-supplied width, height, frame-rate and pixel-rate limits. It ranks
eligible reported profiles by pixel area, then frame rate, then channel order;
missing, unsupported, zero and out-of-limit values remain explicitly
classified. Overflowing pixel-rate calculations are outside limits. The
result is an untrusted planning claim, not proof of codec support, stream
delivery, camera identity, freshness, or authority to change settings.

Strict-remote ts1 job `30106308287922327` passed the camera API contract
(12/12 tests), exited zero, was acknowledged and released source and pair.
Its overlay fingerprint was
`183f152f0ead7d4875bbfc0ac33407cd6ce8be8d811cb25668e5a56a7ba08728`.
The tests cover the G4-shaped report, dimension and pixel-rate restrictions,
missing and unsupported values, no candidate, deterministic ties, overflow and
invalid limits.

The scoped read-only probe now reports the highest complete profile with
resource limits explicitly marked as not applied. Linux build job
`30106308287922328` had remote Cargo exit zero and wrapper exit 102 because
the Mac rejected the foreign executable; it was acknowledged and released
source and pair. Its disposable dependency commit
`5e02059d9c52096512fd416b62a4685299707a7f` contained a camera API source
matching the project source. Separately on ts1, the synthetic process fixture
passed 5/5 cases, including incomplete profile claims. A fresh workspace
matched the probe and fixture source hashes and passed locked offline metadata
resolution.

The SHA-matched Linux probe
`e6bba1d7237728f8cd50cd2def48da22146eb3cb2e0097b9706b1701e80dbec6`
then ran once against the owner's observed G4 on trj using the existing
network-observed certificate pin. It completed read-only login, status,
settings and an in-memory 640 x 360 snapshot; it selected the camera-reported
video1 claim of 2688 x 1512 at 30 fps with no resource limits applied. No
camera setting was changed. A login session may remain until an unknown expiry;
the pin is not independent physical-identity proof. This is not real
full-resolution media delivery, automatic stream setup, a production service,
continuous native recording or retention. The fallback recorder and its two
timers remained active with zero recorder restarts; 16 matching files were
modified in the preceding 15 minutes.

### Setup-observed profile drives synthetic capture (2026-11-12 UTC)

A setup outcome that contains a settings observation can now apply the bounded
reported-profile selector without another login. Outcomes without a settings
observation return no selection. This is advisory: the outcome and any handoff
permit remain caller-owned, and selection does not settle the effect, prove
adoption, authenticate the camera or grant stream authority.

The scoped fleet fixture now gives its simulated camera reported video1, video2
and video3 profiles and verifies the requested controller-address readback.
After setup, it selects video1 for the high-resolution limits and video2 for
the constrained limits, passes that channel into the tracked stream startup,
then archives and reads back the synthetic media with complete source-byte
coverage. A separate simulated camera still sends and decodes video while setup
is held open. The caller explicitly supplies limits, credentials, identities,
operation IDs and effect authority; the fixture does not constitute an
unattended deployment or settle the synthetic handoff.

Strict-remote ts1 job `30106308287922329` passed the scoped fleet test (1/1,
three scenarios), exited zero, was acknowledged and released source and pair.
Its lab overlay fingerprint was
`297b9babca98f02bfd36165a7dfbc203ac7416ddc16aaae32e9a2b175228bae9`
and its disposable dependency commit was
`c12328f7f730145adf09b5342e833afc5f8bd9f3`. Job
`30106308287922330` passed the camera API contract (12/12), including
selection from an already-associated setup outcome, on the same dependency
commit with overlay
`8c365c6cc23f0c4a6ab57b56834b4a18ef504776b117c78101df4f206adbc27c`.
It exited zero, was acknowledged and released source and pair. The relevant
dependency source hashes matched the project checkout; a freshly prepared lab
workspace matched the fixture hash and passed locked offline metadata
resolution.

No physical-camera setting was changed. The fallback recorder and its two
timers were active with zero recorder restarts afterward. This does not prove a
real G4 handoff, direct full-resolution video, uninterrupted native recording,
or 30-day retention.

### Task-scoped setup-to-controller bridge (2026-11-12 UTC)

The scoped TLS lab now exposes a reusable setup-to-controller upgrade path
for an eventual executable. It runs the existing tracked setup and accept
once, then uses one already-drained task-bound entropy lease per controller
TLS attempt. Only an early TLS EOF may admit a fresh connection from the
selected source claim; it never replays setup. The caller retains unused
leases, the setup trace and the effect journal, including on failure or
cancellation. Before setup, the bridge rejects invalid bounds, mismatched
leases, an already-scoped TLS configuration and enabled TLS tickets.
Neither the source/MAC claims nor a successful upgrade authenticate the
physical camera or reconcile its handoff.

Strict-remote ts1 job `30106308287922334` passed the scoped fleet integration
test (1/1, three scenarios) and exited zero, was acknowledged, and released
source and pair. The overlay fingerprint was
`4b0ed133887be51b169bfae03e08a6eae72523f4d63b65120703efc55e5f8a7a`
with disposable dependency commit
`c12328f7f730145adf09b5342e833afc5f8bd9f3`. A synthetic camera performed
one setup, dropped its first controller connection before TLS, then completed
a TLS/WebSocket upgrade with a second lease. Invalid polling bounds, a
different-camera lease and enabled tickets were refused before setup while
leaving the trace and leases unconsumed. The same fixture subsequently ran
the existing synthetic setup, stream and archive scenarios. The Cargo test
output for the library target was truncated in the tool display; the retained
library test binary was run separately on ts1 and passed 14/14 tests. A fresh
lab workspace matched the new bridge and fixture hashes and passed locked
offline metadata resolution.

The bridge is experimental library code, not a standalone recorder. It has
not been exercised against the physical G4 and does not admit the TLS provider
for production, establish identity, reconcile the prior handoff or prove
continuous recording. No real camera setting was changed; the existing
recorder and both related timers remained active with zero restarts afterward.

### Scoped direct trial with profile selection (2026-11-12 UTC)

`src/bin/unifi_scoped_direct_trial.rs` adapts the older bounded direct trial
and its checkpoint, run-ID and archive helpers to the scoped setup and TLS
bridge. It acquires and drains a distinct task-bound entropy lease for the
pinned camera connection and for each controller TLS attempt, disables TLS
tickets, and makes ambient TLS random and key-exchange callbacks panic. With
camera setup enabled and no explicit `--video-channel`, it ranks the setup
outcome's reported profiles within 4096 x 2304, 1–60 fps and the corresponding
pixel-rate cap, then passes the selected channel to the stream request. An
explicit channel still overrides that selection; without camera setup the
legacy default remains video2. No complete admissible setup profile stops the
trial before a stream request. At this revision profile selection occurred
*after* the setup and WebSocket upgrade, so a preceding handoff could already
require reconciliation even when selection later refused; the later preflight
change is documented below.

Strict-remote ts1 job `30106308287922335` compiled the earlier port with
`cargo check`; it exited zero and its acknowledged source and pair were
released. Job `30106308287922336` compiled the subsequent profile-selection
source successfully on ts1 (remote Cargo exit zero). Its wrapper exited 102
because RCH rejected the Linux executable as incompatible with the Mac; the
terminal job was acknowledged and its source and pair released. The fixed
dependency commit was `c12328f7f730145adf09b5342e833afc5f8bd9f3`; the second
lab overlay fingerprint was
`cc2af6c1ca972f793ed523fe8ffe35f1b5520f676faef9ca0b3d5852df1ba61e`.
The retained worker executable SHA-256 was
`bde3ce12187d7b9bdfbe9599f9dd1a20fb15e664054087420c9379aa5d6d173f`.

Separately on ts1, `trial_profile_fixture.py` exercised that binary against a
simulated camera using host-bound unicast sockets and disposable credentials.
It passed 5/5 cases: high profile requested video1; an oversized high profile
selected video2; missing profiles stopped before a stream request; an explicit
override requested video3; and setup through video1 stream request and
synthetic 2688 x 1512 media produced a two-segment clip with six frames that
FFmpeg independently decoded. `trial_media_fixture.py` separately passed the
same two-segment, six-frame synthetic media check without setup. The first
two-segment attempt used an all-keyframe input and failed the existing fixture's
six-frame expectation; the unchanged check passed with the repository's
four-frame-GOP input (`synthetic_g4_resolution_gop4.264`, SHA-256
`96b8a619aee7dd640de62cfac3d67a82dc561410f35dc443d180c53206a9731e`).
These fixtures are laboratory oracles, not physical-camera or production
proof. A newly prepared workspace matched the trial and fixture source hashes
and passed locked offline metadata resolution.

The copied trial remains bounded and experimental: its enclosing-task
cancellation and entropy-worker draining are not qualified for all schedules;
at the revision tested above, run-ID generation used the old ambient provider;
the patched rustls,
`rustls-pure`, and third-party dependency closure have not been admitted for
production. Its network and MAC claims do not independently authenticate the
physical camera. The earlier real handoff and time-sync outcomes remain
indeterminate and must not be replayed without reconciliation. The new path
has not captured real full-resolution G4 video, taken over continuous
recording, enforced 30-day retention, or replaced Scrypted and Docker. No
physical camera setting was changed in this run. The existing recorder and
both associated timers were active with zero reported recorder restarts after
the synthetic tests; that observation does not establish uninterrupted
recording.

### Scoped setup through managed archive (2026-11-12 UTC)

The process fixture now also exercises the scoped executable from synthetic
discovery and already-associated setup through automatic video1 selection,
managed archive rollover and readback. On ts1, all 7/7 fixture cases passed
against the same SHA-matched binary documented above. The video-only case
published and source-checked three 2688 x 1512 segments across two archive
generations, checked retirement and held-tail accounting, and decoded all
five frames in its bounded sequence prefix with the Rust decoder. The A/V
case published three segments, read back 11 synthetic audio packets, and
decoded three high-resolution video frames with Rust. Its AAC configuration
and packet bodies were synthetic; the test does not decode audio or establish
audio timing, camera audio capability or playable audio.

The fixture's local and ts1 SHA-256 matched
`7d6f12382de18cab7b552fa7a7536289b0cb62521b42ed97434778bf8a88912d`,
and the ts1 executable still matched the binary digest above. The existing
recorder and both related timers were active after the test with zero
reported recorder restarts; this does not prove uninterrupted coverage.

The first archive fixture attempt used a three-picture loop and failed the
existing minimum-five-frame check with four decoded frames. The corrected
input matches the older managed fixture's 13-picture, four-picture-cycle
construction and passed without lowering that threshold. These are bounded
simulated-camera tests. They do not settle the older physical effect journals,
test the current G4, establish continuous coverage, or qualify a recorder for
production or 30-day retention. The source bytes omitted by a bounded test and
any unread socket bytes remain unknown.

### Task-bound trial run identity (2026-11-12 UTC)

The trial now generates its public run ID from a one-use entropy lease scoped
to `trial:run-identity-entropy`, rather than calling the ambient provider.
The new lease operation checks task authority and cancellation before and
after the draw, consumes the lease, and clears the remaining pool. It refuses
other resource scopes and insufficient bytes. A deterministic test checked
those refusals and pool clearing, and a run-ID test checked zero rejection and
operation separation; strict-remote ts1 jobs `30106308287922339` and
`30106308287922340` each passed their selected test (1/1), exited zero, were
acknowledged, and released source and pair. An initial test invocation used an
overly exact filter and therefore is not counted as an executed test.

An initial build attempt was refused before admission by a stale worker disk
sample; after the acknowledged pre-admission refusal and a fresh successful
diagnosis, ts1 job `30106308287922341` completed Cargo with exit zero. Its
wrapper exited 102 because RCH refused to copy the Linux executable to the
Mac; its terminal result was acknowledged and source and pair released. The
worker executable SHA-256 was
`5d7fcec73c2209af1354a3748aca6dfcfbc1c5be2efdbb54fc6b203ba409b198`.
The same seven synthetic process cases described above then passed against
this updated executable, including both managed-archive cases. The common
test/build base was `c12328f7f730145adf09b5342e833afc5f8bd9f3`, overlay
fingerprint `9c6b0f1950dce10e95ab75c0725e4b8feda9c38d5f63a492522d7daddece94fd`.
Afterward a resource accessor's documentation was clarified without changing
behavior. These tests do not qualify cancellation of the enclosing trial,
the TLS provider, real G4 media, continuous recording or retention. The
physical recorder and its two related timers were active with zero reported
recorder restarts after the run; no physical camera setting was changed.

### Video-profile preflight before handoff (2026-11-12 UTC)

The setup accept trace now offers an opt-in, single-use requirement for a
complete reported video profile within caller-supplied limits. After two
matching settings reads, the setup owner stores the preflight ranking and
refuses missing or unsupported profiles before preparing or dispatching a
handoff. The scoped trial enables that requirement when the operator has not
explicitly selected a channel; an explicit channel remains an override. The
trial also compares the selected preflight claim with the later setup
observation and stops before a stream request if it changed. This later stop
does not settle a handoff already dispatched. Claims remain untrusted and do
not prove device identity, codec support or media delivery.

The process fixture first reproduced the defect on the prior executable: a
simulated camera with a different controller address and no complete video
profiles received a handoff request. With the fix, the same case refused
without handoff dispatch or controller accept. Two additional cases checked a
successful synthetic handoff with a stable profile and a changed post-handoff
profile that stopped before a stream request while retaining the need for
reconciliation. All 9/9 process cases passed on ts1, including the previous
high-resolution clip, managed video archive and synthetic A/V archive cases.
The fixture SHA-256 was
`3fb168319d25f17e98beb3cb3280edaeb1b4192a4d9e5b70524f62a7446b96ab`
on both the project host and ts1; the Linux trial binary SHA-256 was
`d70e59aefaa31f651ec6508f80aa183627d5f8a1b8e8e7cef791dd2429e1a917`.

Strict-remote ts1 job `30106308287922342` passed the targeted configuration
test (1/1), exited zero, was acknowledged, and released source and pair. Its
retained test binary was then run directly on ts1 and passed all 13/13 camera
API contract tests. Job `30106308287922343` completed the Linux binary build
with Cargo exit zero; the wrapper exited 102 when RCH correctly rejected
copying that executable to macOS. It was acknowledged and released source
and pair. Both jobs used base `c12328f7f730145adf09b5342e833afc5f8bd9f3`
and overlay fingerprint
`dbfe6d60d6640aa396d011951450af6331f4a42acd8c5d82621729701cf3df9e`.
No physical camera setting was changed; the existing recorder and both
related timers were active with zero reported recorder restarts afterward.
The prior physical effects are still indeterminate, and real G4 video,
continuous native recording, retention and production admission remain
unverified.

### Fleet profile preflight and route withholding (2026-11-12 UTC)

The same profile preflight can now be configured on the single-use setup
trace used by fleet work. When configured, a missing or unsupported profile
stops before handoff preparation, and the fleet marks the route ready only
if the returned setup observation still selects the same reported profile.
A changed profile leaves the returned handoff outcome with its original
permit for reconciliation. A fresh trace is required for a fresh setup
attempt; leaving the optional preflight unconfigured preserves the existing
explicit-channel behavior. Profile claims are not device authentication or
proof of video delivery, and this is not unattended enrollment.

Strict-remote ts1 job `30106308287922350` passed the fleet integration test
(1/1, four scenarios) on base `c12328f7f730145adf09b5342e833afc5f8bd9f3`
and overlay fingerprint
`a2371a8ac9486ec6525924f23fb4c44758331444cbd1cae1c7dde2996be91795`.
It exercised limited and full-resolution profile selection in the existing
multi-camera flow, then changed the selected profile in a synthetic camera's
post-handoff settings and verified that the route remained unavailable and
the outcome remained caller-owned. The same-source Linux trial executable
SHA-256 `927adab9507b29d7e965f9a63aaa01a78abb3bb958ea9209b6cd1ab747b12208`
passed the nine single-camera synthetic process cases on ts1, including the
pre-effect refusal and high-resolution archive checks. These test inputs and
effects were synthetic.

Focused reference tests used the same base and overlay fingerprint
`061f50352e206c82d851f3ef083ac1d230a1f59e099be4a239a8939df2d81fa7`:
job `30106308287922351` passed the changed/missing-profile comparison test
(1/1); job `30106308287922352` passed seven setup/handoff cases with three
worker-specific cases ignored; those three ignored cases were then run
directly on ts1 with a locally assigned private address and passed 3/3; and
job `30106308287922353` passed 13/13 camera API tests. These successful jobs
exited zero, were acknowledged, and released source and pair.

The test history includes important limits. Jobs `30106308287922344`,
`30106308287922345`, `30106308287922346` and `30106308287922347` aborted
with test-thread stack overflow before a fleet verdict. A debugger located
the fault in the large synthetic fleet fixture's async state machine. A
16 MiB diagnostic test stack passed; the current fixture explicitly uses
one bounded 16 MiB thread, which is not a production stack qualification.
Job `30106308287922349` then failed with an address-in-use error; after adding
socket-stage diagnostics, the next job passed, but the original collision's
exact cause was not established. These failures are not counted as passes.
No physical camera was modified; the existing recorder and both timers were
active with zero reported recorder restarts afterward. Real-camera native
video, continuous recording, 30-day retention, unresolved historical effects,
and production TLS/cancellation qualification remain open.

### Automatic retry classification (2026-11-12 UTC)

Pre-effect retry safety and automatic retry suitability now have separate
markers. The queue's automatic path additionally requires a selected transient
setup error and the exact completed operation; explicit scheduling remains a
separate caller decision. Both the reference pump and laboratory supervisor
use the automatic path. Automatic timers retain the existing bounded policy,
revalidate the operation, and never rearm a prepared or interrupted effect.

Strict-remote ts1 job `30106308287922354` passed the synthetic fleet test
(1/1, four scenarios) using base `c12328f7f730145adf09b5342e833afc5f8bd9f3`
and overlay `ba3771e900809db823f9a8aec7286b9456bd13c7f5afcfc56b0cc12f277f7b76`.
Job `30106308287922355` passed the focused classifier (1/1) on that overlay;
the retained binary separately passed the rearm-state test (1/1). Job
`30106308287922356` passed seven setup cases, with three worker-interface
cases ignored; the retained binary ran those three directly on ts1 (3/3).
Job `30106308287922357` passed the fleet test again (1/1, four scenarios)
with stricter assertions and overlay
`65e0e1f2dfe56e06b771b0e6a5aa0ce70dcf7ac80ea0eb1fdf694d82422edeb5`.
The latter verified the exact synthetic EOF and HTTP-status failure types,
automatic scheduling only for EOF, explicit scheduling for the HTTP refusal,
and the changed-profile route refusal. The test uses a bounded 16 MiB fixture
thread; it does not qualify a production stack. No physical-camera setting
was changed. On checking, the existing recorder and both associated timers
were active and the recorder reported zero restarts; this is not proof of
gap-free coverage. Login retries may leave sessions with unknown expiry.

### Pre-hello clock hypothesis through archive (2026-11-12 UTC)

`trial_profile_fixture.py` now compares two synthetic scenarios on the
same setup-to-controller path. After an actual synthetic handoff, the peer
sends an uncorrelated pre-hello time-sync request followed by a new request
correlated to the immediately preceding controller reply, with
`responseExpected` set. Under the default conservative policy the second
request receives no answer and the disconnected process reports the
correlated request and a clock effect requiring reconciliation. Under the
explicit `--bounded-continuing-clock` policy both requests receive correlated
replies; the peer then sends hello, accepts automatic video1 selection and
pushes synthetic 2688 x 1512 AVC. The native Rust path publishes and reads
three video segments across two generations and decodes five frames. The
existing fixture also sends a further time-sync request after stream setup.

The strict-remote ts1 binary build, job `30106308287922358`, completed Cargo
successfully but returned wrapper code 102 when RCH refused to install the
foreign Linux executable on macOS; the terminal result was acknowledged.
The isolated Linux executable SHA-256 was
`a181af42911788c45ce8483f05f7cbca8f613e6598ec010bcb5b8c7201e5b5e8`
before and after the fixture run. Separately on ts1 the process fixture passed
11/11 cases, including the two new comparisons and the existing clip, video
archive and synthetic A/V cases. The fixture SHA-256 was
`fe523fd8a085054c128de5bda1f8fc601c155fa34aff87f65596fe4a248fb450`
on both hosts and before and after execution; the synthetic AVC SHA-256 was
`96b8a619aee7dd640de62cfac3d67a82dc561410f35dc443d180c53206a9731e`.
The media fixture and pre-hello helper hashes were respectively
`36dcdc0fa19b8fca217bd1fa12623082941259aa5ea5ef39ddfe14e99c6edcd0`
and `6f9807a2c71e4ac95a6891d83c23677d84865ecc2405a4efddfe33a5f626599d`.
The process fixture ran separately over host-local sockets, not as part of
the RCH build. The existing recorder and both timers were active with zero
reported recorder restarts afterward; no live setting was changed.

This is a hypothesis test with synthetic credentials and video. The prior G4
trace did not determine whether its correlated clock message referred to the
preceding reply, and its earlier handoff and clock effects are still
indeterminate. No live camera, independent physical identity, production TLS,
continuous native recording or retention was established by these results.
