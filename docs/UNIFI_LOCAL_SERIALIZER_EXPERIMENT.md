# UniFi local serializer experiment

## Question and alternatives

Can a G4 send its high-resolution track to an FSS-owned listener after a
camera-local partial settings request, without changing its controller? The
existing local settings endpoint accepts some partial updates, but this exact
serializer field and its restoration semantics have not been qualified on the
camera. A successful HTTP response alone would not establish that the stream
was changed or that the existing recording was unaffected.

Alternative outcomes include rejection, silent ignore, a different serializer
shape, changes to shared audio or other tracks, and a transient stream that
cannot be restored from the reported prior value. Readback, direct media
receipt, and observation of the existing recorder are distinct evidence.

## Current implementation

`unifi_direct::http_stream` constructs a single-track request tied to the
camera/session, destination, framing, lease fence, and the digest of all three
observed serializer values. The body omits the controller, other tracks, and
video codec setting. The codec is an expectation bound to the request identity,
not a setting written by this request.

`camera_api` and `camera_http` provide an experimental dispatcher requiring a
journal-backed one-use camera-setting effect and live authority on each write
and flush. A partial write or failed response fences the session. A successful
response forces a full serializer readback before other operations, but neither
response nor readback automatically settles the effect.
The plan also has a same-session, authority-checked comparison for unchanged,
target-only, and other-track changes. These shapes do not say whether the
requested destination was applied, or whether the change was caused by FSS.
It can also compare the selected track against the fields in the exact request:
additional object fields are allowed, but destination arrays must have the
same length and order. A matching claim can predate the request and does not
prove delivery, causality or settlement.

A separate restoration plan retains the selected track's prior serializer
value in private memory and prepares an independently journaled setting
request after a matching, target-only forward readback. It refuses an absent
prior value, unsupported scalar values, changed other tracks and stale or
unauthorized observations. Explicit null is represented as null, but whether
the physical camera applies it as a restoration is unknown. The plan does
not durably retain the old value, prove camera merge semantics, restore shared
audio or settle either effect.

An encrypted pre-change checkpoint is being added to retain the three prior
serializer values and the exact proposed forward body. Its authenticated scope
binds camera and certificate claims, original request, preconditions and
baseline; the scope and caller-supplied key must be retained independently.
The nonce comes from the scoped runtime under an explicit authority whose
implementation is responsible for cryptographic entropy and nonce uniqueness.
This code does not use Keychain. A real key provider, automatic protected
storage, post-restart restore planning, independent camera identity, and
physical-camera behavior are not yet established. The initial remote build
stopped before compilation due to a dependency lock mismatch; the corrected
v12 build and tamper/cold-reopen tests passed as recorded below. The subsequent
v15 snapshot also passed its synthetic build and fixtures. It includes a
comparison of a recovered checkpoint with an independently admitted new-session
observation. The comparison can
identify changes and requested-field matches, but does not authenticate the
camera, settle an effect, or authorize a restore. No checkpoint was captured
from the physical G4.

The initial planning snapshot passed two synthetic tests on a strict remote
worker: one-track request shape and rejection of changed baseline, peer,
listener, fence, framing, and codec claims. The guarded-dispatch and loopback
HTTP fixtures are separate tests and must not be inferred from the planning
tests.

An initial guarded-dispatch snapshot compiled on remote worker `hz2` and passed
2/2 synthetic tests: refusal of stale or denied requests before a write,
mandatory readback after a complete write, and fencing of a partial write.
Its journal remained committed in both cases and the deletion guard observed
zero attempts. This snapshot predates the expanded HTTP-owner fixture; it does
not qualify that fixture or the camera's response to the request.

The expanded dispatch snapshot compiled on `hz2` and passed 4/4 synthetic
tests, including a loopback HTTP owner fixture and an unsuccessful response.
The owner fixture independently denies the serializer capability, then allows
the one-track write, forces full readback, and has the peer return the old
settings. The tests retain the committed journal obligation; none confirms
that a physical camera accepts the request. The tested binary SHA-256 was
`421afd9f641d5db525de7ed4512e051265b1379efa91b07744262122d506faf4`.
The deletion guard observed zero attempts. The snapshot's `camera_api.rs`,
`camera_http.rs`, `http_stream.rs`, and dispatch test SHA-256 values were
`e78ae5185c551418337efae468b1866161b23ac8ab21d94324c6f7b9e4f5895b`,
`4963eeb9c460695fa9fbfa8ce26eea70b4c885f28b85704461ca7752e05a59e0`,
`76d52dd48d4cb1b90ff4cfc4d18340cd5e8f22510e01fcb2f4ea6f5aeadbc4d6`, and
`90e124c2a5b4bdf16c5b16c37728af9fbc585bb46f4f0071f5c8a9a40ba8d5e8`, respectively.

The subsequent readback-comparison snapshot compiled on `hz2` and passed 3/3
planning/comparison unit tests and 4/4 dispatch integration tests. Its unit
and integration executable SHA-256 values were
`87f4bef9e73bfb6d2eb83037aafba2bdf170b3e868284e1cb62736921c1ad5a6` and
`bb4bd2c1162dad7a539d891da22c1185989770defb6dc486058d95fa9fc37c0f`.
Its `http_stream.rs` SHA-256 was
`80addb3d51cb09847653ce6366c7a13c59d4377790fbfaa2b3f00ec44ee57afe`;
the other source hashes above were unchanged. The deletion guard observed zero
attempts. These are fixture results, not a live-stream or restoration proof.

The requested-field comparison snapshot compiled on `hz2` and passed 4/4
planning/comparison unit tests and 4/4 dispatch integration tests. It reported
nonmatching destination, stream name, audio setting, missing field and extra
destination, refused denied disclosure, and distinguished a request that
already matched the baseline. The unit and integration executable SHA-256 values were
`b7d1185e3eb55fb3b2874394f21f9898f5c0b66a8a87aff4e015c67125cdb4d5` and
`94e3af8974f47513eb9f90ce480f5434689c36d5dd1631fccc2697f265226423`.
The snapshot's `http_stream.rs` and `camera_api.rs` SHA-256 values were
`e7646685d7a06ef397c0deefeb46de02554f7c0c2a2bb0c8f79adace6a17b342` and
`5b829a09a405cf40847ea319e09811e4056490072ed07dd43d5550c21674622c`.
The deletion guard observed zero attempts; no physical camera was changed.

A subsequent integration-only snapshot, with unchanged production source,
passed 5/5 guarded-dispatch tests on `hz2`. Two loopback cases execute the
owner's full settings/write/response/readback sequence: one returns the
unchanged baseline, the other reports the requested serializer fields. Both
are compared through the plan, and both leave the effect journal committed.
The test source SHA-256 was
`d23148bf296c569ee749469363e2343cc8ac22613a657aca003eb21901f3fcc7` and
the executable SHA-256 was
`b1b1a5c5138ba3408931c7a2a72ded5a5aa3bc99fa249c63e1d6674c92e9ba65`.
The deletion guard observed zero attempts. This fixture does not demonstrate
that a real camera implements this local HTTP operation.

The initial restoration snapshot compiled on `hz2`; 6/6 plan unit tests and
5/5 existing dispatch tests passed. These include semantic JSON retention of
an object, explicit null, and refusal for absent, unsupported or unexpectedly
changed tracks. The unit and integration executable SHA-256 values were
`34d09300196d3b8e41aa83ae9b5c1ad40a7b3911ada687cdee12489cd6e98aff` and
`8eeada72651c99d096fc64b931af93033bcc1bcc2b365afa0c20efaa3e7fb686`;
the tested `http_stream.rs` SHA-256 was
`2b63f60f25bb2940728ee991879a7f3b8e244f6322ee51a40ce66f364b013a29`.
The deletion guard observed zero attempts. A newer round-trip fixture must be
assessed from its own result; these results do not prove real restoration.

The first expanded forward-and-restore loopback fixture passed 4/5 cases. Its
new case stopped before network I/O because the synthetic journal rejected
equal prepare and commit timestamps for the restore effect. Its test source
SHA-256 was `d5283ebaf5075e47d257a4bfe7ea9f23aede60b7a51633148f8891e0b640c768`;
the deletion guard observed zero attempts. A revised fixture uses strictly
increasing effect and task timestamps; its result is separate from this failure.

The corrected round-trip snapshot then passed 5/5 dispatch tests on `hz2`.
Its loopback peer received a forward setting request and a separately
journaled restore request, reported the previous serializer value on a final
readback, and left both effects committed rather than settled. The fixture
prepares the restore permit from an anticipated synthetic readback and checks
it against the actual fixture response before dispatch; this is not a live
device recovery workflow. The corrected test source SHA-256 was
`0725a1f8fbcd9add9f817a6e0beb676894a2de2cb8d0eca1f7e6210013c2db9a` and
the executable SHA-256 was
`ea49247a88e21ac8962fd46b9a4014e04e8955873bbfe0826fe0858970f75412`.
The deletion guard observed zero attempts. Camera behavior, durable custody,
shared audio, and continuity across restoration remain unproven.

The same production source also passed 15/15 existing camera API tests and
20/20 ordinary handoff tests on `vmi1149989`; the six interface-dependent
handoff cases passed separately in an isolated network namespace on `ts1`.
The exact handoff executable was copied create-only and SHA-256 verified as
`544797054f3edf19e3ed3be52852e6c9dfda91a47b55126f1624c429337c0f59`;
the camera API executable SHA-256 was
`ba40aee85b4d5aafc309af29f382e9e9e82981e1cda5134b324a87a0e4c19a55`.
Both invocations' deletion guards observed zero attempts. These regressions
do not qualify physical-device behavior or a complete replacement.

The encrypted-checkpoint v12 snapshot compiled with `--offline --locked` on
`hz2`. Its seven serializer unit tests passed, including a private staging
spool reopen, wrong key and scope, tampered nonce and ciphertext, and denied
access; all five guarded loopback dispatch tests passed separately. The unit
and integration executable SHA-256 values were
`de7ccd7e9ba91249663292982114d2bb33ac15a496306621f416f8a529d61473` and
`d29e744dde677b6f0a9da7612a02647e59f89652609361947b64c7ec6cf824bd`.
The deletion guard observed zero attempts. The tested checkpoint source
SHA-256 was `e5edb0b92ebdefadd6924bc744e4862638ecd97d98a536bcef24910fb2518999`;
the later scope accessors in the current worktree require their own build and
tests. The checkpoint remains a fixture-tested component, with no production
key management, durable nonce policy, post-restart restore authorization, or
physical-camera validation. It does not settle any earlier effect.

The newer candidate recovery-comparison snapshot has checkpoint source SHA-256
`6401a5560e4ee22651a3fb5b88378ddeeb453c181e7d2a92660b190c43362eba`.
Its strict-remote build `9253469360607986726` was refused at disk-budget
admission on `hz2` before execution (exit 120), so no test result is claimed
for it. The v15 snapshot includes this candidate. The method compares
preserved values to a caller-admitted new
session without requiring the old session generation, distinguishes changes
to other tracks, and compares the requested fields. Camera and certificate
arguments are claims supplied by the caller, not authentication. The older
v13 build was admitted from queue `9253469360607986717` as job
`30097323753214384`; its source does not include this comparison. Neither
candidate reopens or reconciles the original
journal, and neither constructs or dispatches a post-restart restore.

The later v15 candidate adds a read-only match between the checkpoint scope
and an exact operation in a cold-recovered, reconciliation-only effect owner.
It checks the separately supplied journal head and preparation digest, effect
class, request digest and precondition digest; it returns the journal state,
not proof of the camera outcome or permission to dispatch. A fixture now
exercises a genuine journal close/reopen and rejects a live owner, changed
head, preparation, preconditions and denied inspection. Strict-remote queue
entry `9253469360607986730` was admitted as job `30097323753214360` on `hz2`;
the locked offline build exited zero, then 7/7 serializer unit tests and 5/5
dispatch/journal integration tests passed on that worker. Its
checkpoint and test source SHA-256 values are
`84f81f0abc23283e2ac3fcddeb8f2df3a52c70fb8a43f1ea327ccd26cac0d73c` and
`2c022c930beecd77c03a0ec1435afe1f0c0b8e56d38230ef49f97e360e9b6bcc`.
The executable SHA-256 values were
`cf86f016c3c5a876652a0d54f9c3b8f5f97777fc845169c84b689ef1545b094d` and
`17ad69a9107f2cc53fb8da199515a8cb10c34d6bbbc3e02098c1662fe64fea41`;
both deletion-denying traces recorded zero attempts. These are synthetic
results, not a physical-camera capture or settlement.
The expected pins must be independently retained; no such anchoring is
established for the prior physical G4 effects.

The v16 candidate adds a separate post-restart restoration plan. It requires
an exact cold-recovered forward operation in verified state, all operations in
that journal terminal, a newly admitted session and current serializer binding,
a target-only readback matching the retained forward request, and an exact
match to the caller-reconstructed forward body. It refuses absent and scalar
prior values. The plan grants no effect permit; independent fresh authority,
lease, journal and dispatcher remain necessary. A synthetic fixture is staged
to exercise reconciliation, cold reopen, changed peer/session and independent
reconstruction of the restore request. Strict-remote job `30097323753214371`
compiled v16 successfully, and 7/7 serializer unit tests and 5/5 dispatch
integration tests passed on `hz2`. Source SHA-256 values for the checkpoint and
fixture are `78da1b5c27103939a712c3f664bcdc4f718d6439a89436a85183ea1181b6167f`
and `eff9433efa055c9d7fff5ce502aad35972cc4a6f4a014687c33498b2e506809e`.
The corresponding executables were
`960930d025ff7a2ec21d304b259a247b70f9be1805eb0be2bb502909d62fe7e0` and
`6b56274db34bfde50211a297d7786911cf39caaf890884970b5ea30804a69577`;
both deletion-denying traces recorded zero attempts. These tests do not address
the v16 request-identity gap described next or establish physical behavior.
It does not establish physical camera restore semantics, shared audio behavior,
independent identity or protected key storage.

Review found that v16's body comparison alone does not bind the requested
video codec, which is part of the original request identity but absent from
the JSON body. It must not be used as an exact-forward-request match. The v17
candidate additionally recomputes the original request digest from the prior
peer, session generation, framing and supplied stream configuration, and adds
negative fixtures for changed codec and generation. The v17 checkpoint and
fixture SHA-256 values are
`d1dde2dca7b3e65bb47fb8b44a8d6bb1bffe443b19457deb171d49af2d667f1a` and
`eb4f3b42823222cd1d15cfb2416d3927829aed8704f5615e4f913e9c5129579b`;
that snapshot was admitted from queue `9253469360607986742` as job
`30097323753214375` on `hz2`. Its locked offline build exited zero; 7/7
serializer unit tests and 5/5 dispatch/journal integration tests passed,
including the changed-codec and changed-generation refusals. The respective
test executable SHA-256 values were
`5dca1e6adf9feee374eede84b3d390c690d2d57e80ea163fdae6ebb845b885b6` and
`1e17d3748d1b3e39ea2b01331ec7042a7cb8235871502f89f18a79312d90c4ce`.
Both deletion-denying traces recorded zero attempts. This is synthetic
evidence; the physical G4 has not received or restored this request.

The v18 candidate connects checkpoint staging to the experimental HTTP
serializer dispatcher. `Stored::capture_and_stage` encrypts the exact bound
baseline, stages it in a caller-owned spool, re-reads the ciphertext and places
the spool's verification hold. A start request now requires a matching `Stored`
value before the one-use permit is claimed; a missing or mismatched value is
refused before transport polling. The staged receipt does not guarantee future
object availability, independently retain the key or scope, or anchor the
effect journal. The helper performs synchronous I/O and requires an owned,
bounded blocking caller. Its strict-remote build is queued as
`9253469360607986756`, and its tests are pending. The
four source SHA-256 values (checkpoint, camera API, HTTP owner and fixture) are
`507ef345ff289f2eb752db1487eec791f1508ea5020476c75047dbb601b7a8ff`,
`37e5b6d4254d4536c70c7a7901e86589ecfb6eef44b08855252a09a8a091479e`,
`2bb2591d03d896a4be434e69b92ddc2924177223efe6978c3418845254d28df7`, and
`2aa208e59292580904d0e2736cc597e57ac75d5b3c0cf276d9b3f9c159464884`.
No physical camera has been changed by this candidate.

## Live qualification still required

On 2026-11-14 a read-only re-inventory of the original physical G4 handoff
and time-sync journals found five regular files in each; their late manifest
hashes remained `fa94566200090a7d4b58b5c49733b6906ed5935e0a682e1d25a87fe2087bfeac`
and `8484cb6be55fd66bc8ea6287ebcb0db3a31b14d09f8091afc49ff713e7aaf251`,
respectively. A bounded file-name scan of their two retained trial directories
found no name containing `anchor`, `pin`, or `keeper` among 10 and 9 entries.
The late manifests are not pre-effect anchors; the name scan cannot exclude
anchors elsewhere or under different names. Neither observation settles the
historical effects or grants permission to replay them.

A read-only archive inventory on 2026-11-14 found 10,358 video files in the
root-owned `/bulk/unifi_camera_recordings/g4-instant-fallback`; the newest was
modified two seconds earlier and the oldest was approximately 214.8 hours old.
The inventory used noninteractive privileged access and reported metadata only;
the preceding unprivileged walk could not traverse this private directory and
therefore did not represent recorder activity. This is point-in-time file
freshness and available span, not decoded-frame, gap-free or 30-day retention
proof. It is existing Scrypted-based recording, not direct FSS capture.
Separately, a closed file last modified 124 seconds earlier probed as a
60.000326-second H.264 video at 1280 x 720 and one frame decoded successfully
to a null sink. The probe used privileged read-only access and did not persist
or play media. One usable medium-resolution sample does not prove every file,
continuous coverage, or high-resolution continuous recording.
Read-only inspection of the Python script currently selected by the fallback
service found a `RETENTION` constant of 2,592,000 seconds (30 days); that
script's SHA-256 was
`86087aea0b3c1e8736e80c6b657c2a0c80869cf71a29ad725b1face8096f2435`.
This confirms the configured constant, not that a particular old recording was
deleted at the right time or that cleanup cannot affect other policies.
An independent metadata-only ordering of eligible MP4s modified in the last
24 hours (excluding files modified in the preceding two minutes) found 1,436
files, three adjacent modification-time gaps over 90 seconds, none over 180
seconds, and a largest gap of 121 seconds. Modification times are not camera
capture times; these figures neither prove nor disprove lost video.
`/bulk` reported approximately 3,313 GiB available at this check; this is a
capacity snapshot, not a reservation for future retention.

- Independently establish the camera identity, current settings, listener
  ownership, lease and exact effect authority; retain the actual prior values,
  not just their digest.
- Establish and exercise a restoration strategy for the actual reported prior
  serializer state, including absent and null values, and shared audio effects.
- Prove the remote write and readback behavior on an appropriate fixture before
  considering a single journaled camera operation; do not automatically replay
  an indeterminate effect or use a new identity to bypass an older obligation.
- Independently verify high-resolution direct media and the existing recorder's
  continuity, then reconcile the effect and qualify durable recording and
  retention. This experiment alone does not replace Scrypted or Docker.

No live serializer write is claimed by this document.
