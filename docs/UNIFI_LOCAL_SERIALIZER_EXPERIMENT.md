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
v12 build and tamper/cold-reopen tests passed as recorded below. A newer source
snapshot remains queued for its own build. No checkpoint was captured from the
physical G4.

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

## Live qualification still required

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
