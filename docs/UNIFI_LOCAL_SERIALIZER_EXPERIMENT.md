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

The [reference project's own protocol overview](https://github.com/xuio/scrypted-unifi-direct)
describes camera-pushed extended FLV and full-resolution snapshots decoded from
a live keyframe; its RTSP endpoint is provided by the controller-side plugin.
This supports prioritizing a native owned push receiver and keyframe decoder.
It is the author's general account, not proof that every G4 firmware lacks an
alternative interface or that a particular physical request is safe.

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
`30097323753214384` and compiled successfully; its tests were not run and its
source does not include this comparison. Neither
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
bounded blocking caller. Its strict-remote build was admitted from queue
`9253469360607986756` as job `30097323753214396` and exited zero; 7/7
serializer unit tests and 5/5 dispatcher integration tests passed on `hz2`.
The test executable SHA-256 values were
`2a2eae24af9455611da9f17d8372c342477997beaa6a7e7d2fbba5367ce6dcb5` and
`95e2b195f5ed76ff3082e90b391192f4fca7aed2f5e36b675baec9c1d0a9955c`;
both deletion-denying traces recorded zero attempts. These are synthetic tests,
not physical-camera behavior. The
four source SHA-256 values (checkpoint, camera API, HTTP owner and fixture) are
`507ef345ff289f2eb752db1487eec791f1508ea5020476c75047dbb601b7a8ff`,
`37e5b6d4254d4536c70c7a7901e86589ecfb6eef44b08855252a09a8a091479e`,
`2bb2591d03d896a4be434e69b92ddc2924177223efe6978c3418845254d28df7`, and
`2aa208e59292580904d0e2736cc597e57ac75d5b3c0cf276d9b3f9c159464884`.
No physical camera has been changed by this candidate.

Key-custody source review found an existing Linux private-credential lease in
`crates/fss-cli/src/bin/fss-capture-rtsp/authentication.rs`. It uses a bounded
read, no-follow/nonblocking open, regular-file and link/mode checks, file and
path fingerprint revalidation, and scoped checks around I/O. Its Linux entropy
boundary checks `/dev/urandom` as the expected character device. These are
useful existing patterns for a UniFi checkpoint key provider. The lease is
private to the RTSP CLI, reads an existing username/password format, does not
create or retain checkpoint keys, and has not been wired into this candidate;
its source and test cases alone do not establish UniFi key custody.

The v19 candidate adds a Linux-only private-file key lease based on that
pattern. It exclusively creates a mode-0600 key file with Linux OS entropy,
syncs the file and private parent directory, and reopens and revalidates file
identity before and after key use. The parent and its ancestors are explicit
caller-trusted boundaries; filesystem permissions do not protect against the
owner, privileged users, rollback, or loss of the device. Failures after file
creation can leave partial files, which are never overwritten or deleted by
the helper. It can feed checkpoint staging, but it does not independently
retain the scope or journal anchors and is not yet mandatory for dispatch.
No real key file was created. The v19 source snapshot built remotely as job
`30097323753214397` and passed 8/8 serializer/key unit tests and 5/5 dispatcher
integration tests on `hz2`. The key fixture exercised creation and cold reopen,
denied use, wrong scope, symlink, hard link, public permissions and short file
refusals. Its test executables' SHA-256 values were
`d347e4f67e9fc2ad3af098a7c8fd7087cb41659d5c14ed3fb657cbab48cd9306` and
`92d9408168d0173d11dfe9743777389a4833f0efed0233b2b3d87d73c939485f`;
both deletion-denying traces recorded zero attempts. These are synthetic Linux
tests, not physical-camera or backup verification. Checkpoint and keyfile source SHA-256 values are
`8a62fac73928e736f24e79b4711f89c7c92c30d0044b9742631ba409ad2816d7` and
`450601a5215fd48a275a5a4d14587a52000628e9ea5fa49f73b647361b06ce10`.

The v20 candidate adds a dedicated retained metadata journal for the scope and
ciphertext digest. A start dispatch requires a live `Anchored` receipt, created
only after a successful append and retained-head check; cold reopening returns
an inspection-only recovery record and cannot recreate that dispatch receipt.
Its caller must choose genuinely separate trusted storage and protect its root;
the type cannot prove physical independence or protect a rolled-back trusted
root. Key-file custody remains optional and is not yet bound to this receipt.
The v20 source snapshot was admitted from queue `9253469360607986764` as job
`30097323753214403`; its locked build exited zero and 8/8 serializer/key unit
tests plus 5/5 dispatcher/metadata integration tests passed on `hz2`. These
fixtures included a cold-reopened metadata journal and wrong-pin refusal. The
unit and integration executable SHA-256 values were
`cc5520166d02aad6ca0c581a93abda2b4f64ff65e76eeab2480de3234e533efa` and
`d294255fceb9805741989eda221981f7a1806c7ddfb40d9542be4fbc043434c2`;
both deletion-denying traces recorded zero attempts. This is synthetic evidence,
not physical storage independence or real camera operation. Its checkpoint, keyfile, camera API, HTTP owner and
fixture SHA-256 values are
`a360a53c52229939ad2baad1b829cad61f741f32ebe2a1ce3961426e67d15e91`,
`450601a5215fd48a275a5a4d14587a52000628e9ea5fa49f73b647361b06ce10`,
`dc8d9e1587213736bf0be7bce6f85d37bca618aa85ab32855e16054fff7bf166`,
`9ae836bb71b29fe202081022720d1e4fc8e3320a0373009804f25b5a497b3a51`, and
`c0d288440f240ebc754940bd37fc3505d0007c91be6a9560488d6cd04a6efb19`.

The v21 candidate tightens this path: creating the live anchored receipt now
requires a matching Linux private-key lease and a fresh spool re-read whose
ciphertext authenticates under that key, before the metadata journal append.
The fixture includes a wrong-key refusal before journal append. This still
depends on caller-trusted paths and does not protect against later key loss,
privileged interference, rollback, or loss of the storage device. Its dispatch
fixture is Linux-only; a corresponding macOS key provider is not implemented.
The v21 source snapshot built in strict-remote job `30097323753214406`; 8/8
serializer/key unit tests and 5/5 dispatcher/metadata integration tests passed
on `hz2`, including wrong-key refusal and metadata cold reopen. The executable
SHA-256 values were
`b36fe8a9012a350688e64abf1d0b507ef20f5b1fbebd14c5a04ad38161a35df5` and
`d90397dd1a7d44658f782dcd420578aaa50336b8ac59ac98776fd18e445b2291`;
both deletion-denying traces recorded zero attempts. This is synthetic Linux
evidence, not physical-camera behavior. Its checkpoint and fixture SHA-256 values are
`e8860cb360543020dd6882375b51e7a4fc92dd8359f32a4a66fd6b09fa0308ca` and
`60e112748f4ac8fea1b3fb66cc211b7987fd1c767f7498f373da237314a16866`.

The v22 candidate composes the guarded HTTP serializer owner with an already
bound native media listener. It checks the listener address, sends one
journaled request, requires the complete response and a matching target-only
readback, then returns the claimed permit, private readback and task-owned
incoming pipeline. Refusals retain the permit and distinguish whether a write
may have occurred; cancellation still requires journal reconciliation. A
loopback fixture is staged to send an FLV header through the accepted listener.
The candidate does not authenticate the incoming peer by itself, validate
media, publish recordings, settle effects, or establish camera support for the
HTTP request. Strict-remote job `30097323753214420` is building the snapshot;
the fixture has not run. The source
SHA-256 values for the module declaration, media owner and fixture are
`a1232aae610a0c9d796b5936855d2f3808fe9c18539dc36654e0b5eaac509a74`,
`c065db79f7b85b8b3070c8ef6a72438793d971b514b12dd20b556cd28e62e823` and
`049ebaad32b4a1b65ed0d3f21ccd73135a3ca74efec8d8a369202a497cff379b`.
The v23 fixture adds wrong-listener refusal before a write and unchanged-readback
refusal after a potentially effective write. The production media module is
unchanged from v22; the new fixture SHA-256 is
`3cede391068f0de0148aabda9f75a14753cfe959ce9a33396a1d21b68f81d068`.
The v23 request `9253469360607986770` exited 103 before compilation because the
selected worker had no free slot; the fixture did not run. The v24 fixture
retains these refusal cases.
The v24 fixture further sends synthetic 2688 x 1512 AVC in FLV through that
path, assembles an in-memory fragment and attempts a Rust frame decode. It is
a synthetic source, not a live camera recording or retention proof. The v24
fixture SHA-256 is
`1b3e9a8f7caf7019598889d94cafc8feb5c64ae917b88d865e92953b8aba9c39`.
Strict-remote job `30097323753214428` built the snapshot on `hz2`; 8/8
serializer unit tests and 6/7 integration tests passed. The unchanged-readback
refusal passed, while the high-resolution listener fixture failed with
`Ingress(Source(BudgetExhausted))` before media decoding. Both deletion-denying
traces recorded zero attempts. The integration executable SHA-256 was
`6b027f5682547063b4500f36859ff8baa2fbcc384b6515ce6249c0082fbe2523`.

The v22 build completed, but its fixture did not pass: 8/8 serializer unit
tests passed and 5/6 integration tests passed; the native-listener test failed
with `Ingress(Source(BudgetExhausted))`. Both deletion-denying traces recorded
zero attempts. Inspection of the TCP ingress shows that it requires both byte
and network-byte budgets; this fixture supplied only the latter. The v24
snapshot had the same fixture budget and independently failed in the same way.

The v25 candidate supplies a finite byte budget to the fixture and also checks
listener chunk, total-byte, and wait bounds before issuing the camera request.
It reuses the listener's own bounds so the preflight cannot diverge from the
subsequent accept check. The fixture attempts five invalid configurations,
requires a no-write refusal and then reuses the permit for its real loopback
attempt. This protects against deterministic configuration errors after a
camera write; it does not prove a socket will be available, authorize an effect,
or resolve cancellation, readback, peer identity or restoration. The v25
candidate's first remote request exited 120 before compilation because the
worker's protected disk-reservation floor could not admit it. The same
unchanged snapshot was resubmitted as `9253469360607986774` and started
compilation on worker `vmi1153651`; execution is not a completed build and its tests have
not yet run. Its listener,
media owner and integration fixture SHA-256 values are
`ed53108e18f803cd131745cd4acbb5fc20f7af60444a5b9b9d4be46abc069ef5`,
`c8ad3e29e13a3b9c7363bc80339222e144c5c497f0b99580e48e6e1bf36c46f3`, and
`07f6a710d88a736c153ee605a4ff5450db2b4f3fc02ab5bd2d4ea4d61ee2c38c`.
The worktree's media owner subsequently changed only the `Preflight` variant's
documentation to mention the newly checked bounds.

The v25 strict-remote build completed on `vmi1153651`; its tests passed 8/8
unit cases and 6/7 integration cases, with zero deletion attempts in both
traces. The high-resolution test progressed beyond the former byte-budget
failure but failed with `Mux(UnverifiedPicture)` before decoding. The fixture
had repeated the same IDR NAL as several purported pictures; the muxer requires
distinct picture identities. The next fixture uses the four distinct IDR NALs
already present in the same synthetic source. This is a fixture correction, not
evidence of a successful stream, physical device behavior, or recorder fix.

The HTTP-started pipeline can now be attached to the existing native
video-only and separate-source archive workers without constructing a
controller WebSocket session. The driver retains the committed serializer
effect and readback, pauses media while archive work is outstanding, returns
all publication outcomes, and requires explicit retry after a failed attempt.
It rejects mismatched camera/source bindings and streams that have already
emitted records. A fresh stream or completed source-preserving prefix probe is
eligible for attachment. End-of-stream and changed AVC configuration stop the
driver and retain the remaining owners for the caller; this is not yet an
unattended recorder, audio capture, rollover, identity proof, live device
qualification or 30-day retention.

An initial bridge snapshot passed a strict-remote `cargo check` on `hz2` in
job `30097323753214438`; this was compile-only and preceded the fresh-stream
attachment check. A subsequent v27 snapshot adds a synthetic HTTP-to-video
archive/readback/decode fixture and that attachment check. Its first two remote
requests exited 120 before compilation because `hz2` and `vmi1227854` could
not admit the requested disk reservation. The v27 fixture has not run. Its
bridge, pipeline, video-session and fixture SHA-256 values are
`1ec90673aca39bdc5da8c92a783cc8743ab5d160b1ac2dc004826a20e62ae4b6`,
`ba3304f3cc1cb2f9496af6be7e59b35991a5f1451ebd7bc1482acb1300751135`,
`2e1c812ed8c138ba15e1b291312bca026d6163ad63cae6630fae578d45546269`, and
`265cf83c0337df6d9952d00df2cd07287811426d93c989a87b316a34afdcaad4`.
The staged v28 snapshot additionally retains the camera claim bound to the
HTTP start and requires the archive binding to match that claim. Its fixture
attempts attachment to independently prepared storage for another camera
before attaching the matching storage. This is a caller-supplied claim, not
independent camera authentication. v28 has not yet been built or tested; the
media owner, archive bridge and fixture SHA-256 values are
`385ec0e428b5c55fbdbd3d2fc7d57e4a2da7b076e6dcb4aa13d2e56a5403c888`,
`e17cc587982e3f3cc39b7a1d1dd2920aab118a8464d20fecad8202d3011e4f08`, and
`bee01678fcb4a153a4db53d17ec130b013c9821fea6d86070a381ace52681b97`.
The staged v29 snapshot additionally refuses attachment while an installed
name probe has not completed; otherwise ordinary media processing would discard
that probe. Its synthetic fixture checks the refusal, explicitly abandons the
probe, then attempts the matching archive attachment. Strict-remote request
`9253469360607986788` was cancelled before admission after its fixture error
was found; the wrapper exited 130 and its terminal status was acknowledged.
The fixture did not run. Its pipeline and fixture SHA-256 values are respectively
`764e1e169049630d5b4b187e4f8fa34c0ad2d36dd22df8082a8fdd96ac444d1d` and
`b851ea12c694bfc037405190660c3eeadf6f072cbacb1bea335f7acb81c7b334`.
Before execution, source inspection found that the v29 name-probe fixture
requested 1 MiB while the packet API permits at most 256 KiB. The staged v30
snapshot corrects that fixture input. v30 has not been run.
The v32 candidate also fixes the repeated-IDR fixture and makes the connected
owner's effect, readback and pipeline non-replaceable while attached; callers
can explicitly detach all owners or use source-preserving probe methods.
This protects the local binding from accidental owner substitution, not from
an untrusted or misidentified physical peer. Strict-remote job
`30097323753214452` built the v32 candidate on `vmi1153651`. The exact binary
passed 8/8 unit tests and 7/8 integration tests under deletion-denying tracing,
with zero deletion attempts in either trace. The corrected native listener test
assembled and Rust-decoded one synthetic 2688 x 1512 frame; the archive test
failed with an undifferentiated `HTTP media archive stopped unexpectedly`, so
publication and readback remain unproven. This was a synthetic peer, not a
physical camera. The integration executable SHA-256 was
`5c13a4636f4fbe7b6897919672f063baa8bcf96081f39a613e1a59ca742cf65b`.
The media owner and fixture SHA-256 values are
`017f541c88d8edda2a3ecab2c1df8fd59e30e0459a09cee7fa0d561a7546c07e` and
`ad8cd692644c009d1565d7291477f3b14a36a4c33a15f94d43e014de9f662620`.
The staged v33 candidate waits on a running archive worker with the same bounded
timeout used for media, instead of returning immediately in a polling loop. A
dropped wait leaves the worker owned for a later join. Its fixture configures
a one-thread blocking pool, occupies it, checks that the bounded wait returns
while the source remains retained, then releases the pool and requires archive
publication and readback. Strict-remote request `9253469360607986792` was
cancelled before admission in favor of the newer v35 candidate; its wrapper
exited 130 and its terminal status was acknowledged. v33 was not built or
tested. Its
bridge and fixture SHA-256 values are
`23cdd4508fafdb9ac546f689b23ebfce36de2ac6b255f81a4e455f2a1871a077` and
`3472b9738ffa1908f565b0c3f56faa8179dd70d1066ac586db168d7145ecb03c`.
A separate native-runtime contract now exercises a timed-out join of an
already-started blocking worker, then releases it and requires the same result
exactly once. Its source SHA-256 is
`49dceef1248de12e7301008c43ca1725070f05ff20104ad5891fd8700f6bedfb`.
Request `9253469360607986791` was cancelled before admission to select another
worker; its exit 130 was acknowledged. Its replacement
`9253469360607986798` was also cancelled before admission to try another
worker, with exit 130 acknowledged. The next request reached `vmi1149989` but
exited 120 at disk admission before compilation. The contract has not yet run
and does not by itself qualify the archive driver.

The v35 candidate checks that every archive driver step uses the same canonical
task that accepted the source, before starting storage or polling media. The
new task-binding query refuses unbound, inactive or different task state. Its
fixtures attempt a different authority with the same textual task ID, then
continue under the original task. This does not establish a physical camera
identity or a common clock mapping. Request `9253469360607986794` was cancelled
before admission in favor of v36; its wrapper exited 130 and was acknowledged.
The new binding and fixtures have not been built or tested. The TCP ingress,
archive driver, runtime binding fixture and archive fixture SHA-256 values are
`29c4d50d814fd2fc471cd8c67f9b05ccb28697a03b38ff87f255b820f898f152`,
`f41768c93d12eaa40a50129d728118f07957efb4de456c4939e1cc24db56866d`,
`604f329ec04b28538aa82f7c176e0feea3d6c8c18d0e2394ceb915c964e65153`, and
`ecda3fe703f02f78772f3929ad4ee25aaa4e054f90149423044c6d7bd8cd87d0`.
The v36 candidate additionally requires the HTTP owner and native listener to
share their exact task/clock mapping and resource before dispatch; its fixture
tries different mappings and resources using an I/O owner that reports any
poll. It also reports specific archive refusal categories to diagnose the v32
failure. Request `9253469360607986801` was cancelled before admission to try
another worker, with exit 130 acknowledged. The next request reached `hz2` but
exited 120 at disk admission before compilation. Private worker targets were
seeded from copies of completed v32 and v24 targets as build caches; no v36
compilation or test result is claimed. The listener, HTTP owner,
media owner and fixture SHA-256 values are
`ddf59e387d6511ebcfb928d073a5c38e7eec1eeeaf7074924194c6032d2872c5`,
`d590bc1be96017b2816520582725c96d38b5defb32c0070b253be62698cf8de0`,
`351dcb16003b5d42200ccebcaab0a8ad003831e22d486c3eccb5fa7d36065a04`, and
`c456e75fd9995391af8e031dd66d59c0dabec06bd4cd0f415907329ff04303ad`.
An isolated local copy of the v36 snapshot was hash-checked before a remote
request to `trj`; job `30109207290183937` exited 103 before source or execution
admission because another task owned an overlapping source namespace. No
recorder settings were changed. The same snapshot is now compiling on `ts1`
in job `30109207290183938`; the redundant queued v36 request on the other
fleet was cancelled before admission with exit 130 acknowledged. The ts1 build
and all its tests remain pending.
The v32 archive fixture used the exact registry `asupersync` 0.5.0 default
runtime, whose documented blocking-pool maximum is zero and whose builder
creates no pool in that case. The archive worker requires a pool, making the
missing explicit pool a plausible cause of the undifferentiated failure. This
is source-level diagnosis, not a captured refusal reason; the newer fixture
explicitly provisions one worker and reports distinct errors.

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
The separately retained five-file forensic copy of the time-sync journal on
`trj` also matched the late time-sync manifest. It preserves bytes, but cannot
replace the original namespace or supply the missing pre-effect anchor.

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

On 2026-11-14 the isolated v36 snapshot built on `ts1` as RCH job
`j-30109207290183938`. Its synthetic HTTP-stream unit tests passed 8/8, its
HTTP dispatch integration tests passed 8/8, and the runtime async and drained
blocking tests passed 7/7 and 5/5 respectively. The integration suite included
publishing, reading back, and decoding synthetic 2688 x 1512 video through the
native archive path. The test process ran with deletion syscalls denied: three
attempts to unlink temporary root files were denied, and artifacts were kept
under `/data/tmp/fss-unifi-v36-tests-20261114-receipt01` on `ts1`. This is
fixture evidence, not a camera test or proof of unattended service or retention.
The later combined startup preflight is not part of that v36 result and is
tested separately below.

The v37 snapshot including the combined startup preflight built on `ts1` as
RCH job `j-30109207290183955`. Its synthetic tests passed 8/8 HTTP-stream
unit, 9/9 HTTP dispatch integration, 7/7 runtime async, and 5/5 drained
blocking cases. The integration executable SHA-256 was
`fc0e328f0e5db23ec01b2401d7d1c0db916997bbdfbc2ee154fba814ae303375`.
Deletion-denying traces retained under
`/data/tmp/fss-unifi-v37-tests-20261114-receipt01` show three denied attempts
to unlink test archive temporary roots and no other deletion attempts. This
validates the tested synthetic paths, not a live camera handoff, unattended
recording, audio, onboarding, or 30-day retention.

On 2026-11-14 the read-only laboratory trial gained a redacted distinction
between a missing serializer, explicit null, object and unsupported scalar or
array. It reports the shapes only after two full serializer bindings match;
it does not print private values or their digests. The source SHA-256 is
`b3ea663777d864a96928ace189c1782194c99b34f5ce01acef198195efeead07`.
The first strict-remote build stopped before compilation because the copied
laboratory lockfile was stale. A subsequent offline build regenerated that
isolated lockfile and completed on `ts1` as job `j-30109207290183978`; the
lockfile SHA-256 was
`ace3512c3ed4512f075f2c427091a8338d482a9297bd0acf58efc9c7b309ec10`.
The focused Rust shape test passed 1/1 with zero deletion attempts. A regular
binary then built as job `j-30109207290183987`; its SHA-256 was
`7f83db5622dc80c49b1afc22b62cf86090fb78572d13351da9f5860defd6548c`.
In a private network namespace, a fake camera fixture passed 2/2: stable
values reported object, null and missing; a changed private destination with
the same public shape was refused without reporting shapes. The fixture trace
showed no deletion syscalls. Two earlier fixture attempts timed out before the
fake camera received discovery because their network namespaces lacked the
required synthetic neighbor entry; they are not successful fixture evidence.

The same binary was create-only copied and hash-verified on `trj`, then used
for one bounded read-only observation of the physical G4 with the existing
network-observed certificate pin and local credential. The two serializer
bindings matched, and the redacted shapes were `[object, object, object]`.
The high-resolution profile was reported as video1 at 2688 x 1512, 30 fps;
the destination shapes were `[NotReported, TcpOnly, NotReported]`. These are
camera claims, not proof that video1 is inactive or that a serializer update
and restore will work. The run prepared no camera effect and the deletion
trace contained no calls; its private trace is at
`/data/unifi-g4-recorder/fss-serializer-shapes-live-20261114-01/trace` on
`trj`. Immediately afterward the existing recorder was running with restart
count 5. One observation cannot establish future continuity or independent
physical identity, and login-session expiry remains unknown.

The v38 HTTP archive driver adds a bounded `run_slice`: each nonterminal media
or archive result must be accepted by an observer before another step; a
refused event is returned intact, and terminal or actionable events go to the
caller. The caller still owns worker drainage and must explicitly authorize
retries. It is not a reconnecting recorder or retention service.

The isolated v38 snapshot built on `ts1` as strict-remote job
`j-30109207290183996`. Its selected HTTP-stream unit tests passed 8/8 and its
HTTP dispatch integration tests passed 10/10. One integration case uses the
combined preflight/start owner all the way through synthetic 2688 x 1512
publication, archive readback and Rust frame decode, while exercising the
bounded runner's refusal and yield paths. The integration executable SHA-256
was `d0dd4ca59fb0fd5f2c62ee6887e64d1c301f18a98085dd86d2f8d703e8081793`.
Deletion-denying traces at `/data/tmp/fss-unifi-v38-tests-20261114-receipt01`
record six denied attempts to unlink temporary roots from the two archive
cases; no such deletion occurred. This fixture does not establish direct
physical-camera capture, unattended operation, audio, or 30-day retention.

The v38 library-wide Clippy run exited 101 with 30 denied `expect` usages in
other existing library code and 859 warnings; it did not establish a clean
lint gate. It also flagged the new runner's argument count. The subsequent
v39 snapshot groups the slice bounds and archive admissions into one config;
its source and fixture hashes are
`52adb3ac7edbf8b5debd5aaf794493a60042cbcbe046f5ae705a452419e2814f` and
`7b2d1ba17754b4d3c847d22665877fa5a3fb4fa0305bd49b263bcadcd0a558b6`.
Strict-remote job `j-30109207290184005` built it on `ts1`; the exact resulting
executables passed the same 8/8 selected unit tests and 10/10 integration
tests. The integration executable SHA-256 was
`cea3bf098abace1b24eff596677556de5dcfc12bb5aace688cff95726336952f`.
The v39 deletion-denying trace records six denied temporary-root unlinks,
retained under `/data/tmp/fss-unifi-v39-tests-20261114-receipt01`. The v39
revision has not passed a library-wide Clippy gate.

The read-only laboratory command now has an optional encrypted HTTP checkpoint
and a separate process can reopen and authenticate it. It stores the observed
serializer values and a planned forward request before any camera write. The
local root and its ancestors remain trusted, and the plan is based on the
requested listener address; this observation does not bind a live listener or
authorize dispatch or restore. The checkpoint worker is bounded and drained on
timeout, and partial artifacts require inspection rather than blind retry.

The isolated checkpoint snapshot built on `ts1` with offline-resolved
dependencies as jobs `j-30109207290184101` (test binary) and
`j-30109207290184106` (command binary). Its scoped serializer-shape unit test
passed 1/1. The command binary SHA-256 was
`6c7625dc4a07f192300a220588eaeb3d2f309fa405d376eb855c19c2857d56f9`;
the exact offline lockfile SHA-256 was
`ace3512c3ed4512f075f2c427091a8338d482a9297bd0acf58efc9c7b309ec10`.
In a private network namespace the fake-camera fixture passed 2/2: the stable
case saved a checkpoint and a second process authenticated it; the changed
serializer case refused before creating the checkpoint. The successful
fixture's key mode was 0600, and a bounded search of its 12 files found none of
the selected synthetic destination and credential strings. The deletion-denying
trace recorded zero deletion calls. Fixture and trace remain on `ts1` at
`/data/tmp/fss-unifi-checkpoint-fixture-20261115-03`. This is synthetic
recovery evidence, not evidence of a physical G4 write or restore.

During the subsequent recorder check on `trj`, the existing Scrypted-based
recorder was active but its restart count had risen from 5 to 7. Logs showed
the video process exiting followed by systemd restarts; the cause is unknown.
A later file freshness observation showed recent output. These observations do
not prove uninterrupted recording or that the Rust changes caused the restarts.
A read-only `ffprobe` of one file modified 156 seconds before the probe found
H.264 video at 1280 x 720; this is one fallback recording, not a coverage or
frame-decode qualification.

The next laboratory checkpoint revision binds the requested native listener
before constructing the forward plan and holds it through checkpoint creation.
It closes that listener when the read-only trial ends; the retained checkpoint
does not keep a listener alive or authorize a later camera write. The isolated
source built on `vmi1153651` as offline job `j-30109207290184121`; its command
binary SHA-256 was
`9432b69b1f0cdbc74e689c7732038de39d896033d6f15f170fefe6ba098c76c8`.
The simulated-camera fixture passed 3/3 cases: stable settings with cold
checkpoint authentication, changed settings refused, and an occupied listener
port refused before checkpoint creation. The deletion-denying trace at
`/data/tmp/fss-unifi-bound-fixture-20261115-01/fixture.trace` on that worker
recorded no deletion syscalls. The physical camera was not used in this run.

The same hash-verified binary was subsequently copied create-only to `trj` and
run once against the physical G4 in read-only checkpoint mode. Two serializer
bindings matched, the high profile was reported as 2688 x 1512 at 30 fps, a
separate listener bound, and a second process authenticated the saved
checkpoint. The camera received no setting write, and the deletion-denying
trace contained zero calls. The checkpoint and trace are retained in the
private `trj` directory
`/data/unifi-g4-recorder/fss-bound-checkpoint-live-20261115-01`. At the end of
the trial the listener was closed, the existing recorder was active, and its
restart count remained 7. The camera certificate is a previously observed
network pin, not independent identity; the checkpoint root is a trusted local
storage domain. This does not prove actual stream delivery, restore semantics,
continuous coverage, or attribution of any earlier recorder restart.

The laboratory checkpoint owner now exposes a start adapter that retains its
plan, baseline, key, spool, and journal while passing the same bound listener
and the caller's committed permit into the native video archive driver. A
preflight refusal returns the original capture inputs and permit; a later
refusal retains its media or attachment owners. The adapter does not settle the
camera effect, reconnect, or provide an unattended service. The current trial
command does not yet call this adapter for a physical camera.

In isolated v41 strict-remote job `j-30109207290184141`, the integration
target built on `ts1` and passed 10/10 tests. Its combined case bound the
listener, created and anchored the checkpoint through the owned worker,
rejected a mismatched listener, reused the returned owners, accepted a
synthetic camera stream, published the native archive, read it back, and Rust
decoded a 2688 x 1512 frame. The executable SHA-256 was
`21c2bab033e5e900c520e8703d492eae118d844632ede793623a2f783afe09df`.
The deletion-denying trace under
`/data/tmp/fss-unifi-v41-tests-20261115-receipt01` recorded six denied
temporary-root unlink attempts; no deletion occurred. This is synthetic
evidence and does not establish physical camera writes, restoration, audio,
retention, or reliable continuous operation.

The laboratory command now has an explicit `--lab-http-record` mode, requiring
the existing automatic pinned-setup fence, anchored effect journal, and an
encrypted HTTP checkpoint. It retains the same bound listener, prepares a
journaled one-track camera setting effect, starts the native receiver, archives
one video fragment, reads it back, and decodes a picture. It records neither
audio nor continuous coverage; it reports unfinished source bytes and leaves
the camera setting effect unresolved for reconciliation. It does not restore
the previous physical camera setting.

The first isolated end-to-end command fixture stopped because its loop failed
to recognize buffered video as normal progress. The revised command built on
`ts1` as job `j-30109207290184152`, executable SHA-256
`f017e2eb4394f1d72e933fa7542b257d11e3cc48621fa1072b681840d22361bd`.
The isolated fake-camera fixture SHA-256
`0ff4c82d1db43455f424ed3898955a6ab518ee7369fd86be3c95027a8d18c648`
passed 4/4: successful synthetic 2688 x 1512 archive/decode with one unresolved
effect, changed serializer refused before writing, occupied listener refused
before writing, and nonmatching readback refused with one unresolved effect.
The fence inspector independently reopened the two effectful test histories;
for the two pre-write refusals it correctly refused an absent effect checkpoint
rather than proving an empty history. The deletion-denying trace at
`/data/tmp/fss-unifi-record-fixture-20261115-04/fixture.trace` on `ts1`
recorded three denied temporary-root unlinks. No physical camera setting was
written by these tests. A later revision retains owners around archive readback
failures; its build and tests are separate from this result.

That later revision built on `ts1` as offline job `j-30109207290184162`,
executable SHA-256
`bc964fe5fba38d23b5aeee4dd0daefaa7f08b2018114c02abf3059067d1400b0`.
Its isolated command fixture passed the same 4/4 synthetic cases, and its
read-only observation regression passed 3/3. The command fixture's trace at
`/data/tmp/fss-unifi-record-fixture-20261115-05/fixture.trace` recorded three
denied temporary-root unlink attempts; no deletion occurred. These results
precede the pending changes to G4 trailer framing, in-band AVC, and reported
dimension checks; those changes require their own build and tests. None of
these tests exercised the physical camera or established restoration.

The HTTP recording laboratory now accepts the existing opt-in structured G4
trailer policy and in-band AVC mode, and requires the selected profile's
reported dimensions to match the encoded stream. The first synthetic G4 run
failed because the fixture supplied a 12-byte rather than 16-byte extra
trailer. After correcting the fixture, the next run reached archive readback
but failed because that verifier used the non-in-band parser for an `avc3`
clip. The verifier now selects the matching parser explicitly.

The corrected version built on `ts1` as offline job `j-30109207290184180`,
executable SHA-256
`d584b1e291692b4706891cb6022dbdc6c6d05c998280221de07e84022b3c5b3e`.
The separately copied fixture SHA-256
`37380e6a77e213c47fb60a94df6dd35d5a8c9c3e9d88736a88f6d0f1a60d0822`
passed 7/7 isolated synthetic cases: ordinary and G4-style 2688 x 1512
archive/decode, changed baseline and busy listener refusals, bad readback,
dimension mismatch, and bad trailer. The 3/3 read-only serializer regression
also passed against this executable. The fixture trace at
`/data/tmp/fss-unifi-record-fixture-20261115-08/fixture.trace` recorded nine
denied temporary-root unlink attempts; the observation trace recorded no
deletion calls. These are synthetic results, not a physical G4 stream,
camera-setting restore, continuous recorder, audio, or retention proof.

The runtime now exposes task-owned verification of a committed effect against
the coordinator's already-recorded observation. A refusal returns the original
permit, and task ownership, lifecycle, deadline, coordinator, and exact proof
checks still apply. This API does not establish independent evidence or wire
the camera experiment to effect settlement or restoration.

An isolated `fss-runtime` test workspace built on `ts1` as job
`j-30109207290184192`; its exact `execution.rs` SHA-256 was
`6c87f0a929fa4157bd6e89532347c9dda69d02a48c1b6d4e1018ecdf36f95a79`,
and its contract test source SHA-256 was
`e53f3ae5f18f8ad74a6c4c1b970603e2a3200001f4a0e4c343c3bf16ffc552da`.
The test executable SHA-256 was
`cf0410c331727220d068e51ecc77915c01f5e2edda04bc1a1d7c1ddd541aea43`.
Under a deletion-denying trace, 5/5 tests passed, including refusal before
observation, refusal of a different proof, retained permit reuse, and refusal
of verification by another task; the trace recorded zero deletion syscalls.
This establishes the task-effect contract only, not physical camera effects.

The HTTP recording trial now keeps the detached committed permit and original
private readback together with the other owners until the trial ends. After
archive readback and decoding it obtains a fresh serializer readback over the
same authenticated HTTP session, compares its complete binding with the
original post-write readback, and rechecks that the requested target-only
change is still present. A changed value or unavailable observation refuses
the trial and retains the owners in the error until it is reported. This is
two reads from the same session, not an independent device identity or a
durably retained postcondition proof; the effect remains unsettled, and these
in-memory owners are not durable after process exit.

The isolated build on `ts1` was job `j-30109207290184196`, executable SHA-256
`ca095498dc0a0ced1a6497f4f824288e5632a609d22be187376b0ee6c7290980`.
The synthetic fixture SHA-256
`7f8a56d0fce2266ea9299e091ad08ea3ce91c7bcdc5fb2e99654827c0a8613ba`
passed 8/8, including a post-capture change to another track that refused with
the effect unresolved. The read-only serializer regression passed 3/3. The
recording fixture trace at
`/data/tmp/fss-unifi-record-fixture-20261115-09/fixture.trace` recorded 12
denied temporary-root unlinks; no deletion occurred. No physical camera was
used in these tests. Verified effect settlement and camera restoration still
need independently retained observation evidence and separate authorization.

An expanded fixture against that same binary added a disconnect before the
post-recording read. Its SHA-256 was
`577fad44402a5701b5e49a8619d871ffa81cb6dc304d79bf8d234d847b72793b`;
9/9 synthetic cases passed, including refusal with the effect unresolved when
that read was unavailable. The trace at
`/data/tmp/fss-unifi-record-fixture-20261115-10/fixture.trace` recorded 15
denied temporary-root unlinks; no deletion occurred. This does not exercise
the physical camera or independently settle the effect.

The trial now also captures the consistent post-recording serializer values
in a second encrypted, separately pinned checkpoint under the original
checkpoint directory. It constructs a non-dispatched snapshot plan whose
request digest must equal the original plan's request; the new plan uses the
observed values as its baseline. Checkpoint failure refuses the trial and
leaves the original effect unresolved. The checkpoint is a same-session
camera claim in an operator-trusted local storage domain; it is not proof of
device identity, causality, a separate physical storage domain, or permission
to dispatch the snapshot plan. Cold recovery has authenticated each checkpoint
individually, but has not yet independently compared the two recovered values
and scopes or reconciled the effect.

The isolated build on `ts1` was job `j-30109207290184202`, executable SHA-256
`10da37cd9f53f9eaa1caa9dfbaa4e56552bdecd4b819cf57ebbba70d8f1e0d1d`.
Fixture SHA-256
`5414187116d578b81605cd0e8c49e6727fbac31a66f950b1f488d172a7a627ba`
passed 10/10 synthetic cases, including a blocked checkpoint directory; the
successful cases authenticated both checkpoints in separate processes,
checked the observation key's 0600 mode, and found no selected synthetic
private strings in observation-checkpoint files. The read-only regression
passed 3/3. The recording fixture trace at
`/data/tmp/fss-unifi-record-fixture-20261115-12/fixture.trace` recorded 18
denied temporary-root unlink attempts; no deletion occurred. This is not a
physical camera capture, restoration, or continuous recording proof.

The next laboratory revision adds a read-only cold comparison of the two
checkpoints: it requires matching camera, certificate, request and channel
claims, identical forward JSON, the requested selected-track change, and no
other track change. These checks do not independently authenticate the device,
establish causality or settle the effect. The initial build was admitted as
`j-30109207290184213`; its negative fixture tried to copy checkpoints and
failed before comparison because the retained journal binds its original
physical namespace. The corrected command accepts both original paths rather
than copying them.

The laboratory HTTP recording path now also accepts one to eight bounded
fragments and retains each completed publication for readback. The first
multi-fragment run decoded two synthetic fragments but the suite as a whole
failed at the same copied-checkpoint test; it was not a full pass. The
corrected combined version built on `ts1` as job `j-30109207290184224`,
executable SHA-256
`cda2b09a8c06958aeea8e968eb468748b48fc8239308d03675cf453999d6681c`.
Fixture SHA-256
`3bf491709a00b5ad0cebe52b34e4f753208eea96b92debb5398adcb0bec62e26`
passed 11/11 synthetic recording cases and 3/3 checkpoint-pair refusal cases.
The ordinary and G4-style streams each published, reopened, and Rust-decoded
two 2688 x 1512 fragments; an early end after one publication reported failure
and left that root present. Cold comparison accepted the matching snapshots
and refused an unchanged baseline, a different request, and a missing
observation. The read-only serializer regression passed 3/3. The trace at
`/data/tmp/fss-unifi-record-fixture-20261115-16/fixture.trace` recorded 23
denied temporary-root unlink attempts; no deletion occurred. These are
synthetic results, not evidence of physical capture, gap-free recording,
reconnection, audio, 30-day retention, effect settlement, or restoration.

The combined recovery inspector now reopens the two original checkpoint
namespaces, compares their saved observations, and checks the original
checkpoint's camera/certificate claims and exact request and precondition
digests against the run-specific effect in the recovered setup-fence journal.
It reports the existing state without settling or redispatching the effect.
The roots and certificate remain operator-selected trust inputs; matching them
does not independently establish a physical device or observation causality.

The isolated build on `ts1` was job `j-30109207290184244`, executable SHA-256
`f59d36891c6e1de5cabef244fac760deed5416860896e4d59dcbe85fac7b6914`.
Fixture SHA-256
`6517f22ddbdc5c47d3e7f14f3225a825f377aa57a9420cada87de0435b765a87`
passed 11/11 synthetic recording cases, 3/3 checkpoint-pair refusals and
3/3 checkpoint-to-journal cases, including a wrong run's fence. Matching
journals remained committed and unresolved. The trace at
`/data/tmp/fss-unifi-record-fixture-20261115-17/fixture.trace` recorded 23
denied temporary-root unlink attempts; no deletion occurred. This is not live
camera, fresh-session, effect-settlement or restoration evidence.

A later laboratory revision adds a read-only fresh-session comparison against
a retained pre-change checkpoint. It requires the current camera and
certificate claims and compares the current authorized serializer observation
with the original values and request. It does not dispatch or settle an effect.
The isolated build on `ts1` completed as `j-30109207290184255`; executable
SHA-256 `8a9b0df738b3fc8f4efff9efbc53a4f04b08efe38f20c3f450e04c5c10989a61`.
Fixture SHA-256
`efb25488632d0b18f37045b44de3ec91a25985a94de0e24b67961395ccf0c31f`
passed 11/11 recording, 3/3 checkpoint-pair, 3/3 journal-matching and 2/2
fresh-session synthetic cases. The fixture trace at
`/data/tmp/fss-unifi-record-fixture-20261115-18/fixture.trace` recorded 23
denied temporary-root unlinks; no deletion occurred.

The same hash-verified binary was run once on `trj` in read-only comparison
mode against the physical camera and the prior bound checkpoint. Discovery
matched the previously observed certificate pin, settings were read, and the
camera reported video1 at 2688 x 1512, 30 fps; the comparison then refused
with a generic error. A separate read-only inspection authenticated the saved
checkpoint. Neither result establishes why comparison refused, physical
identity, full-resolution delivery, effect settlement or restoration. No
camera setting was written, and the live and checkpoint-inspection traces
recorded zero deletion calls. The existing recorder was active with restart
count seven and recent files afterward. A later revision separates claim and
authority refusal diagnostics; it is not yet tested against the camera.

Read-only inspection of the authenticated checkpoint's metadata found that
its certificate digest matches the current pin, while its camera claim
matches the cached neighbor's MAC and address rather than the pin-derived
claim. Repeating the read-only comparison with the original claim type
succeeded: all three serializer values were unchanged from that checkpoint,
and the checkpoint's proposed stream fields were not present. The binary's
`identity=pin_claim` label was overly broad for this run: selection used the
MAC/address claim and TLS used the pinned certificate. The source label has
been corrected but that label change has not yet been built. This observation
does not resolve the earlier handoff or time-sync effects, independently prove
physical identity, or demonstrate full-resolution video. Both live traces
recorded zero deletion calls; the existing recorder remained active, restart
count seven, with recent files. The read-only comparison does not write
camera settings.

The diagnostic revision built as `j-30109207290184257`, executable SHA-256
`095e4e2662dfde489f51913d6b0963d598381b9d0add0a52f9de7e2b5a3617fc`.
Fixture SHA-256
`c5289982d8b046c8c081fe73cf0efae5283e2f3c3101094f3101282319eb581e`
passed 11/11 recording, 3/3 checkpoint-pair, 3/3 journal-matching and 3/3
fresh-session synthetic cases, including rejection of a different pinned
certificate. The trace at
`/data/tmp/fss-unifi-record-fixture-20261115-19/fixture.trace` recorded 23
denied temporary-root unlink attempts. This binary was not used on the
physical camera; the physical result above used the earlier binary.

The direct HTTP media path now has a separate bounded A/V bootstrap driver.
It enables in-band AAC tracking before processing, pairs each audio event with
the recorder result from the same source step, and retains the connected
stream, first segment and committed camera-effect permit. An incomplete
bootstrap returns its owner; an unconsumed second audio configuration fences
the driver and returns the event and source custody. This hands an idle A/V
sink to its caller; it does not publish, decode or play audio, reconnect, or
prove the physical camera uses the tested AAC profile.

The initial synthetic stream produced `NoAudio` because every video sample was
a keyframe and the first segment ended before the AAC sample. A subsequent
fixture with intermediate video frames reached A/V bootstrap but used an
audio-frame limit larger than the MP4 policy allowed. After correcting both
fixture conditions, the isolated `ts1` build completed as
`j-30109207290184284`. The test executable SHA-256 was
`937a71e92860759ec2eb99101203299479021445a13883c107ab9a38a3ce4177`;
the new driver source SHA-256 was
`977440799bd47e6ca9adf78a90970370a9610e1b7ab23f28dfe9993139837ed2`, and
the test source SHA-256 was
`450598c5f858cc7139431da62ea2dab56fe3ba17e4e401f546fbd8a5a88ee26d`.
The full HTTP dispatch contract passed 12/12, including AAC/video bootstrap
and duplicate-configuration refusal with retained owners. The trace at
`/data/tmp/fss-unifi-audio-bootstrap-20261115-06/test.trace` recorded six
denied temporary-root unlinks; no deletion occurred. The isolated workspace
required create-only transfer of two source files omitted by the RCH
`coverage` directory filter. No physical camera audio was tested.

The HTTP A/V bootstrap now transfers its retained connected owner and first
segment to an idle unknown-time archive worker. It rejects a mismatched source
claim or pending/inactive audio and preserves the relevant source, effect,
storage and recovered-rollover owners on construction refusal. A caller must
still offer the segment, run and drain the worker, and handle every returned
source record; the transfer itself performs no publication. Source keys are
caller-supplied claims and do not independently authenticate a device.

On `ts1`, build `j-30109207290184298` compiled the isolated snapshot. The
HTTP dispatch suite passed 13/13: the new synthetic A/V path published and
read back a fragment with nonzero AAC frames and video samples, found an audio
track, and decoded one 160 x 128 video frame. A zero-work-limit refusal returned
the original connected effect permit, first segment, and storage owners. A
separate existing test published and decoded synthetic 2688 x 1512 video
without audio; neither test proves high-resolution A/V delivery by the G4.
AAC samples were not decoded or played. The source header and other forwarded
records remain separately caller-owned, and this is not a reconnecting or
continuous recording service.

The first archive test run stopped at an earlier preflight because adding a
blocking worker changed its expected refusal; the fixture was corrected. The
next build published and read back A/V but failed a video dimension assertion
that incorrectly expected the separate high-resolution fixture; the audio
fixture's dimensions are 160 x 128. After correction, the full suite passed.
The final executable SHA-256 was
`e13a929e9cf0f15afcee3a275512a5ff0737e520699dc3935b961adf2b2eee67`, driver
SHA-256 was `25e0729dd8dfe1319c72e2aa0ff94ea89ae588617a37bf45ba46970a6e76ff7b`,
and test SHA-256 was
`c4a29e20bf8b3e4c978181abf11305787ca7089309174364c2ba0bec7c19633c`.
The trace at `/data/tmp/fss-unifi-audio-archive-20261115-04/test.trace`
recorded seven denied temporary-root unlinks; no deletion occurred. The
existing Scrypted-based recorder remained active with seven restarts and six
recent recording files at the subsequent check. No live camera setting was
changed, and physical A/V capture, audio playback, continuity and retention
remain unproved.

The HTTP A/V path now has a bounded post-bootstrap archive driver. It lets the
caller offer separately returned bootstrap sources and account for each
publication before asserting that the prefix is complete, then serializes
standalone-source and A/V work with backpressure. It keeps paired audio events
with each decision, retains workers across waits and cancellation, requires
explicit retry after refusal, and stops on changed audio/video configuration.
The prefix seal is an operator assertion, not independent proof that all
earlier source records were supplied. Collecting and accounting for the prefix
while bootstrap is still in progress remains the caller's responsibility.

The first two-segment synthetic attempt had consecutive IDRs with no AAC
sample between them and correctly refused the empty-audio fragment. After
correcting the synthetic GOP and audio timestamps, isolated `ts1` build
`j-30109207290184305` passed 14/14 HTTP dispatch tests. The new case archived
the separate bootstrap prefix, published two successive A/V fragments, read
both back with nonzero audio and video sample counts, and decoded one 160 x
128 frame from each. The AAC bytes were synthetic and not decoded or played.
The executable SHA-256 was
`857cdb8a0a5a72ca97ec5fcd63473da2fb4957fa646abcfd853ece716fefea84`,
the scheduler source SHA-256 was
`e62ff9babe138cf1bffa30015662e813e6c680aba8d4b1ae725c9d8ecc466177`, and
the test SHA-256 was
`f50933d68dc56fb0c14b8bc427a896eb3e84b89bc80842dc63b463ee5005cbd7`.
The trace at `/data/tmp/fss-unifi-audio-stream-20261115-03/test.trace`
recorded ten denied temporary-root unlinks; no deletion occurred. The existing
recorder remained active with seven restarts and six files modified in the
prior five minutes. This is not a live-camera, long-running continuity,
high-resolution A/V, audio-decoding, automatic-reconnection or retention proof.

The HTTP A/V bootstrap now has a coordinator that archives each separately
returned source before reading further media, preserves paired audio events,
and refuses transition while the source worker is pending or running. It
transfers the completed bootstrap and drained source owner to the post-startup
driver, sealing the prefix only after those steps. A source refusal, media
fence, transition failure, or cancellation retains the applicable owners;
the caller must still inspect every returned completion and event. At this
checkpoint it started after a separately authorized HTTP camera-start
operation; the later guarded-start preflight is described below. This is not a
live service or a reconnection mechanism.

An isolated `ts1` build, job `j-30109207290184306`, passed the full HTTP
dispatch suite 15/15. The new synthetic test archived the bootstrap source,
verified that a pending source prevents transition, and then published and
read back two 2688 x 1512 A/V fragments. Both contained AAC sample metadata
and a decoded video frame at that resolution. The AAC bytes were synthetic;
audio was not decoded or played. The high-resolution H.264 fixture was
generated with a local FFmpeg `color` source and libx264 constrained baseline,
seven frames at 25 fps, a three-frame GOP, no B-frames and one encoder thread;
FFmpeg is a fixture generator, not a production dependency. Fixture SHA-256:
`a1342e1879cd66d61accfd6877ba74802fffd62929a1ae0062648a8fe0153244`.
The test executable SHA-256 was
`176617033380fa9e42094a891d59f5274d383b982130259f163b2eb295059060`, the
startup source SHA-256 was
`138a55ea7495ec2b2351ddea6f9179c79d398b32c7b1b721dccf639018140d96`, and
the test source SHA-256 was
`1647db4de3cb298c6082e4f69c4bf078f6a01f080c3ef454a9d6a73bef5ae58d`.
The trace at `/data/tmp/fss-unifi-av-startup-20261115-02/test.trace` recorded
13 denied temporary-root unlinks; no deletion occurred.

A separate Scrypted API options query on `trj` returned a high option
claiming H.264 at 2688 x 1512 with AAC and a medium option claiming H.264 at
1280 x 720 with AAC. The active recorder script explicitly requests `medium`.
This is an exposed option and script observation, not proof of delivered high
resolution, physical camera identity, actual audio, or safe switching. The
probe did not directly request a stream or issue a camera-setting write.
Subsequent inspection of the installed plugin's source showed that the options
method can refresh its selected audio profile and reset existing streams if it
detects a profile mismatch. Thus the earlier description of this query as
read-only was too strong; the query may have had indirect side effects, and
the observed state does not establish whether it did. Afterward the existing
recorder remained active, with seven restarts and six files modified within
five minutes. No previous indeterminate camera effect is settled by this query,
and no live Rust takeover or uninterrupted coverage is claimed.

The HTTP A/V startup now has a pre-write guarded entrypoint. It checks the
task, listener, source and camera claims; requested H.264/AAC; source worker
and journal state; retention identity; configured archive, media, evidence
and static AAC timing bounds; and blocking-pool availability before dispatch.
It returns the original boxed input and permit on preflight refusal. It does
not reserve disk space, establish future retention authority, test source
archive capacity against later work, or verify the AAC-dependent jitter bound
until configuration is observed. At this checkpoint recovered A/V rollover
custody was refused before the camera request because its validation can
perform blocking storage work; the subsequent drained preflight is described
below. This is not a successful live recovery claim.

The synthetic high-resolution test now exercises this guarded start. It checks
seven invalid timing, frame-limit or retention cases and an Opus request,
requiring refusal without polling the fake camera connection; then it starts
the valid synthetic H.264/AAC stream and archives and decodes two 2688 x 1512
segments. The first two builds exposed a stack overflow in the combined test;
boxing the owned start inputs and nested futures let the focused case pass. A
subsequent full run exposed another stack overflow in the existing video
archive branch, resolved by boxing that nested test future. After fencing
recovered rollover instead of performing its storage check inline, the final
isolated build on `ts1`, job `j-30109207290184314`, passed 15/15 HTTP dispatch
tests on the default test stack. Executable SHA-256:
`f97665049ee38937a05afbc1f213b77f96f80bf0d502c9f524fd770569d27756`;
startup source SHA-256:
`e43a0ccbb916858d4a2c45ff6f6abd2f5e077979bab66da6c213c1bf2392a685`;
test source SHA-256:
`2986e224aac500464f1250f0fa4d057cc334c0afdfb0f741492a353ffc443b3e`.
The trace `/data/tmp/fss-unifi-av-preflight-20261115-06/test.trace` recorded
13 denied temporary-root unlinks; no deletion occurred. The existing recorder
remained active with seven restarts and six files modified within five minutes.
No physical camera write, audio decode, long-duration recording, or recovery
qualification is established by this test.

A region-owned recovered-startup worker now holds the exact A/V archive
resources while checking rollover history on the blocking pool. On a completed
successful check it records an in-memory observation bound to the current
journal scope and heads, confirmed pin, transition count and newest switch.
The guarded HTTP start accepts recovered custody only while that observation
still matches, and the subsequent A/V worker attachment consumes it without a
blocking storage read. Each publication still rechecks custody on its own
blocking worker. Cancellation, failed verification, a panic or an uncertain
runtime outcome invalidates the observation; a failed retained-head read
fences the original owner and must be reconciled. The observation is not an
independent storage reservation, device identity, or proof against later
out-of-process changes.

The first synthetic rollover test arrangement overflowed the default test
stack; moving the new recovery scenario into a boxed helper resolved that
test failure. On `ts1`, isolated build `j-30109207290184318` passed five
targeted rollover cases: successful recovered validation and single-use
attachment; failed retained-head verification with custody retained and
fenced; a previously poisoned predecessor; and both journal and keeper
capacity cases. The HTTP dispatch suite passed 15/15 on the same build.
The two synthetic test executables had SHA-256 values
`041db98923b85a0b995494fa445984cfb6b7f5587a11ffaa9112c2561e1fc155`
(recording) and
`4014c1a583472e9153faf2f78880a2205660fae3e34e5e3c2a630ff603aae3bf`
(HTTP). The recovery-worker source SHA-256 was
`d62e47749bd46c5428f4b8f856e19a919a166c3372f98103ce6532569a92f290`, and
the recording-test source SHA-256 was
`c6b6154ea3cca9492b4971b2ff1e5f54f334c697308970275ed1c3abb3728132`.
Deletion-denying traces under `/data/tmp/fss-unifi-recovery-worker-20261115-03`
through `-07` recorded 4, 4, 8, 4 and 13 denied temporary-root unlinks,
respectively. The existing Scrypted recorder remained active with seven
restarts and six recent files. At that checkpoint these tests did not exercise
recovered custody through the full HTTP camera-start path; the later synthetic
test below addresses that part. They do not prove cancellation under a blocked
storage read or qualify physical-camera takeover or long-running reconnection.

The HTTP dispatch test now also constructs two synthetic archived segments and
a retained rollover, then verifies that an unverified recovered owner is
refused before the fake camera connection is polled. A drained worker checks
the retained history, after which the guarded fake HTTP start attaches the
recovered owner and publishes and reads back two 2688 x 1512 synthetic A/V
segments. One video frame from each segment was decoded; AAC sample bytes were
synthetic and were not decoded or played. The older forwarded test records
remain owned by the fixture, which does not establish end-to-end continuity.
Initial test arrangements exposed a default-stack overflow and an incorrect
expected refusal classification; the fixture's synchronous rollover was moved
to a drained blocking worker and the expected binding refusal was corrected.

On `ts1`, isolated build `j-30109207290184324` passed all 16 HTTP dispatch
tests on the default stack. Executable SHA-256:
`7c119739947ef6750b64b6f3af897021d052d8bf94f08aa4908d95b6a8175a1d`;
test source SHA-256:
`98d0444923d8ef1834c72aa1c32b65151d297f8be923926b3a60ccb69653aad5`.
The deletion-denying trace at
`/data/tmp/fss-unifi-recovered-http-20261115-07/test.trace` recorded 18 denied
unlink attempts. The Scrypted recorder was active with seven restarts and six
files modified in the preceding five minutes. This test used a fake camera and
made no physical-camera write; it does not establish actual camera resolution,
audio playback, live recovery, or 30-day recording retention.

### Existing real-camera evidence and recorder check (2026-11-15)

The high-profile option is not merely hypothetical: an earlier G4 clip
captured through Scrypted is documented in `UNIFI_DIRECT_REFERENCE.md` under
“Physical G4 high-profile verification” and “Full-resolution G4 recording:
native 30-frame comparison”. That report also records a 151-frame native Rust
decode whose frame hashes matched FFmpeg. The saved, five-second clip was
rechecked in its owner-selected verification directory: its SHA-256 remained
`2ce702b355fa7d8a56780a5dc881d3c0e68b5a21d2e9db7d0bd8b0cef6b55361`, and
FFprobe reported H.264, 2688 x 1512, 30 fps and 151 frames. This is historical
Scrypted-controlled, video-only capture, not a fresh direct-camera connection.
The separate “Live 2688 x 1512 relay capture in Rust” entry records native Rust
archival of 15 live high-profile pictures through the Scrypted relay; it also
did not establish a native camera-control session or audio capture.

The active Scrypted recorder remained running with seven reported restarts;
six fallback MP4 files had been modified within the previous five minutes.
One recent closed fallback file, stable in size and modification time during
the read, contained a single H.264 video stream at 1280 x 720 for approximately
60 seconds and no audio stream. A separate bounded check of five recently
closed files found all five stable during reading, all five with 1280 x 720
video, and none with an audio stream. These are sample observations, not an
audit of every recording. Read-only inspection of the active recorder worker
found that it explicitly selects video and passes `-an` to FFmpeg, so this
recording configuration excludes audio; that does not establish whether the
camera is currently emitting usable audio. The active fallback
archiver script still declares a 30-day retention interval, but actual
30-day retention and cleanup remain unverified. No camera request or setting
change was made for these checks.

### Fresh passive audio observation (2026-11-15)

Earlier passive G4-derived experiments in `UNIFI_DIRECT_REFERENCE.md` did
find raw AAC and independently decode it using an audio configuration from a
separate relay observation; the original capture did not contain an AAC
configuration, and its connection epoch was not established. This corrects
any impression that physical-camera-derived audio has never been decoded.

On a fresh eight-second passive sample of the existing medium push, the old
ignored AAC-track test refused `TrailerPolicyMismatch` with its strict
`StructuredTrailer16` policy. Separate in-memory inspections observed 323
adjacent candidate gaps of 16 bytes and, in a later sample, trailer bytes
incompatible with both strict zero and strict A/V-flag assumptions. Structural
candidates are not authenticated boundaries, and these separate observations
do not establish why the initial attempt failed. The ignored diagnostic test
now explicitly uses the existing conservative `ZeroStreamId` profile instead;
this does not change the production default or prove the sender's identity.

Strict-remote build `j-30109207290184326` on `ts1` passed seven ordinary AAC
track contracts, with the private-input case initially ignored. The exact
executable then passed that private case on a different fresh eight-second
passive sample, reporting 110 unconfigured AAC samples, no AAC configuration,
324 records and a 16-byte unparsed tail. The initial FLV header and starting
boundary were synthesized, and the test did not decode, play or save audio.
The absence of a configuration in a midstream capture does not establish what
a freshly opened camera stream provides. Executable SHA-256:
`08898caaaf212c6b79a04e7f709797bb6956f6efff5549c21424e278b17899d8`;
test source SHA-256:
`1db732f44d12dc534b6adaea2cd8a140d020c11f3a9f255f806377c41a3caa99`;
AAC-track source SHA-256:
`a6976a911aa50402bc5f321d400cf2394e45cefc92f60d8e9339359fe58148b6`.
The test traces under `/data/tmp/fss-unifi-live-audio-20261115-01` and `-02`
showed no deletion attempts. The existing recorder remained active with seven
restarts and six files modified within five minutes; no camera setting was
changed. Neither the successful heuristic replay nor earlier relay-derived
configuration proves a direct camera session, continuous audio recording,
audio/video synchronization, or 30-day retention.

The separate ADTS diagnostic now accepts an explicit `--zero-stream-id`
option while retaining its prior strict default. Its source-matched,
packet-only laboratory build on `ts1` was job `j-30109207290184327`;
an unsupported command-line option was refused. On another fresh eight-second
passive sample, the Rust diagnostic used that option and the previously
relay-observed AAC-LC 16 kHz mono configuration as a hypothesis, framed 109
source-mapped samples, and returned a 16-byte tail. FFprobe counted 109 audio
frames, and FFmpeg decoded them to a null sink with no reported errors. No
in-band configuration occurred in this diagnostic; the selected framing,
configuration epoch and sender identity remain unverified. Audio was held in
memory, not saved or played, and no camera setting was changed. This is not a
native Rust AAC decoder, an authenticated camera session or recording proof.

The laboratory executable SHA-256 was
`028f54a2818e376e2d7e0ed65b2774b82c1ac653227033e18af7b460c20f6d26`;
diagnostic source SHA-256:
`73919e98f14ee2625a3270f78168a3e18d387b27e28ba923188d5bf525af3be0`;
framing source SHA-256:
`13a6f36adf7bb91c23dec177ba478d4f847e037d044da8e3825e784909dff069`.
The private in-memory orchestration helper has SHA-256
`fd2f4bf508aa21ffbe642c34149cfb77cb3ffd6ae24ad629312a5745b4606642`.
Its deletion-denying trace at
`/data/tmp/fss-unifi-live-audio-20261115-02/adts2.trace` contained no deletion
calls. The recorder remained active with seven restarts and six recently
modified files afterward.

### Explicit unverified AAC configuration in HTTP startup

The HTTP A/V startup and bootstrap drivers now accept an optional, explicit
two-byte AAC configuration through the existing `SuppliedUnverified` archive
path. The ordinary attachment remains in-band-only. This option does not infer
the configuration, bind it to a camera or epoch, or make audio eligible under
an unspecified privacy policy. The guarded start validates the AAC syntax and
its configuration-dependent jitter bound before dispatching a camera request;
invalid values return the original start inputs and effect permit. Attachment
refusals also return the supplied bytes. A later in-band audio configuration
is returned to the caller and fences processing rather than silently replacing
the supplied value.

An initial focused synthetic test passed, then the full HTTP fixture aborted
on a default-stack overflow in an existing video-only case. A separate focused
run of the earlier build reproduced that overflow. Boxing the fixture's large
async operation resolved that observed failure. Strict-remote build
`j-30109207290184330` on `ts1` then passed all 18 HTTP dispatch tests on the
default test stack. The new synthetic case starts without an in-band AAC
configuration, publishes and reads back two 2688 x 1512 A/V segments, checks
that their audio origin remains `SuppliedUnverified`, and decodes one video
frame per segment. Its AAC payloads are synthetic and were not decoded. A
separate case checks that a later in-band configuration halts processing. The
preflight cases reject an invalid configuration and incompatible jitter before
polling the fake camera while returning the original values.

The final test executable SHA-256 was
`9301e12a58155031518cd8f90151a5b1837812d02575cad52a5a4c21e1ea214a`;
the bootstrap, startup and test source SHA-256 values were respectively
`023b97b605d74dac49eaa280de71e1d72e3d65ac9a158884df6779d3f69cb642`,
`e61e129c651c7753120f691ea776044052df5eec8c4053c7a2c105dd86fddaa3`, and
`f39c5885c0f3f831d6da82920afd5a459ff34fb1092fafcbd49a3ba1442d5085`.
The deletion-denying full-suite trace at
`/data/tmp/fss-unifi-unverified-audio-20261115-05/test.trace` recorded 22
denied unlink attempts. The existing recorder remained active with seven
restarts and six files modified in the preceding five minutes. No physical
camera request was made in this test; direct capture, audio synchronization,
recovery under real failure and 30-day retention remain unqualified.

### Camera-derived audio/video through HTTP startup (2026-11-15)

The HTTP dispatch fixture now has an explicitly ignored, bounded private-input
case. It sends owner-supplied FLV through the same fake HTTP camera and native
listener, uses the explicit `SuppliedUnverified` AAC path, archives and reads
back one A/V segment, and decodes one video frame in Rust. It stops after that
confirmed segment; it does not claim all observed bytes were archived. The
private test creates a mode-0600 readback clip under its private temporary root
for a separate decoder check. This test fixture is not a production exporter.

Two separate passive samples, each bounded to 20 seconds, of the existing medium push passed the
private case on `ts1`; each archived 150 video samples and 78 AAC frames and
decoded a 1280 x 720 video frame in Rust. For the second sample, independent
FFprobe counted 150 H.264 frames and 78 16 kHz mono AAC frames, and FFmpeg
decoded both tracks to a null sink without reported errors. The clip's size,
modification time and digest were unchanged during that check; audio was not
played. The first attempt did not run that independent decoder. The camera
configuration and timestamps are not established by these decodes.

The samples used a synthetic FLV header and selected initial IDR; video
configuration came from a closed fallback recording and matched before and
after capture, but its connection epoch remains unverified. AAC configuration
was the earlier relay-observed value supplied as an explicit hypothesis. The
controller and HTTP setting response were simulated, sender identity and
physical capture time were not independently verified, and the A/V timing was
not independently measured. No physical camera setting changed. These results
are not a native camera handoff, continuous capture, automatic onboarding or
30-day retention proof. Private source/archive and readback data remain in
mode-0700 tmpfs directories under `/dev/shm/fss-unifi-camera-http-av-20261115-01`
and `-02` on `ts1`; they are not covered by the fallback retention policy.

The final strict-remote build was `j-30109207290184332`: 18 ordinary HTTP
dispatch tests passed, with the private-input test ignored until separately
invoked as described above. The final executable SHA-256 was
`70386d928e1f021559e6551d26f26fc4bf5fc7654c6cf44d4c6abef781b14767`, and
the matching test source SHA-256 was
`f04c4f204ab91933d4b3a60a99f2aa3a15586eae0d661095ff0834ea9b2201b4`.
The local orchestration and independent-oracle helper SHA-256 was
`1950c36d036d133d41a997cf6a55be03ed682805bdae8dd7747ba9c4fdd34e97`.
The deletion-denying traces recorded 22 attempts for the ordinary suite and
two attempts for each private replay, all denied. The existing recorder was
active with seven restarts and six recent files after the tests.

### Checkpoint-bound HTTP A/V start (2026-11-15)

The laboratory checkpoint adapter now also exposes `start_av`. It retains the
prepared encrypted checkpoint alongside the A/V result, preserves capture and
effect owners on preflight refusal, and carries the explicit unverified AAC
configuration through the existing A/V startup driver. This was a building
block for the discovery trial; the `--lab-http-record` command remains
video-only. The separate experimental `--lab-http-av-record` command added
later is described below. The adapter does not authorize camera
setup, prove camera identity or settle the camera-setting effect.

Strict-remote build `j-30109207290184334` passed 19 ordinary HTTP dispatch
tests on `ts1`, with two private-input cases ignored in that run. The new
synthetic checkpointed A/V case refused a wrong listener, returned the same
capture and effect permit, then started with the correct listener and read
back two 2688 x 1512 A/V segments. Their AAC data was synthetic and was not
decoded. A separate, explicitly invoked checkpointed private-input case used
a fresh passive sample from the existing medium stream: it archived 150 video
samples and 77 AAC frames, and Rust decoded one 1280 x 720 video frame. An
independent FFprobe/FFmpeg check counted and decoded both tracks with no
reported errors; audio was not played. The clip's bytes and metadata were
unchanged during that check.

The controller and its HTTP response were simulated. The header and initial
IDR boundary were synthetic, the video configuration came from a separate
closed fallback recording, and the AAC configuration was the earlier relay
observation supplied as an unverified hypothesis. Neither configuration's
connection epoch, the sender's independent identity, or physical A/V sync was
established. The private archive and mode-0600 readback clip remain under the
mode-0700 tmpfs directory `/dev/shm/fss-unifi-checkpoint-av-20261115-02` on
`ts1`; this diagnostic directory is outside the fallback retention policy.
The real camera received no setting change. The existing recorder remained
active with seven restarts and six recent files.

The executable, checkpoint-adapter source and fixture source SHA-256 values
were respectively
`a352cb7924708c83005f619d3684957277f2d680675a43f254a789da6c2b838d`,
`4648ab56d3f1ba587878381a811b7d410cb4bc384342cff8c35de24fb3d6525a`, and
`f8dccdb1a8fcd1be8d5195390dfbad61ddca58da915536fd5b1787be139dd273`.
The private orchestration/oracle helper SHA-256 was
`6baa565acb1a1316692b9ba3e45a663b73c381a7bb18715f76ebf9affae1b6c1`.
Deletion-denying traces recorded 25 attempts for the ordinary suite and two
for the private replay, all denied. This does not establish a direct camera
handoff, unattended A/V recording, crash recovery or 30-day retention.

### Experimental checkpoint-bound HTTP A/V command (2026-11-15)

The isolated discovery trial now wires the checkpoint-bound A/V startup to a
separate `--lab-http-av-record` path. It requires an explicit AAC source or a
supplied, unverified AAC configuration, an anchored setup fence and an HTTP
checkpoint. The original HTTP recording command rejects AAC options instead of
silently discarding them. The new path archives a bounded number of fragments,
reopens each through the native source mapping and decodes one video frame per
fragment. It performs a separate post-recording serializer observation and
anchors that observation; the camera-setting effect remains unresolved.

Strict-remote build `j-30109207290184336` produced the command executable
`938bdbf6f90248a2dceee62076a589b9176779990c78f583bd8ba5506bb72adb`.
The matching command, A/V runner and checkpoint adapter sources hash to
`304971958415bb0ddab440efc6a04052b11cc05dff7a984835f1f5f40de55ad3`,
`cf83e34306250d895b513b19ab9f3563dec454e753ccf6c72a6e6f9d7fd825ec`, and
`4648ab56d3f1ba587878381a811b7d410cb4bc384342cff8c35de24fb3d6525a`.

The isolated A/V command fixture passed seven cases and two option refusals:
supplied and in-band AAC configuration, repeated in-band AVC parameter sets,
bad readback, short stream, changed serializer observation and conflicting AAC
configuration. The repeated-parameter-set case supplies SPS and PPS with each
synthetic IDR and reads back two synthetic 2688 x 1512 A/V fragments. One video
frame per fragment was decoded; the synthetic audio payloads were not decoded.
The test used a synthetic camera and an isolated network namespace, with trace
at `/data/tmp/fss-unifi-av-inband-20261115-01/fixture.trace` on `ts1`;
15 attempted deletions were denied. The A/V fixture and shared fixture source
hashes were `17c77a8831c373f449319ee8523570affaaea486d53daea26181b110dab138d3`
and `fe83dcf227c54b95829de4233b3277d48e3414e4564a1cb41bcc17f5ccc6a745`.
A separate regression run passed 13/13 synthetic HTTP recording scenarios,
three checkpoint-pair comparisons, three checkpoint/journal cases and three
live simulated observations. Its trace is
`/data/tmp/fss-unifi-av-command-20261115-11/fixture.trace` on `ts1`;
29 attempted deletions were denied. This regression used the earlier fixture
revision; the seven-case A/V run above covers the later in-band AVC addition.

A separate invocation of this command replayed a fresh passive medium-stream
sample into simulated discovery and camera HTTP responses. It archived 150
video samples and 78 AAC frames and decoded a 1280 x 720 video frame. The
camera media, AAC configuration and identity have the same qualifications as
the earlier passive tests above; in particular this exact command run did not
independently decode audio. Its private archive remains in the mode-0700
`/dev/shm/fss-unifi-av-command-20261115-09` directory on `ts1`, outside the
fallback retention policy. No physical camera setting was changed. Neither
test proves physical-camera handoff, continuous capture, automatic onboarding,
recovery, A/V synchronization or 30-day retention.

### Recorded physical G4 high-profile HTTP replay investigation (2026-11-15)

The existing controller had one medium push and no high push at a read-only
socket check. To avoid changing a live camera setting, the first attempt used
the historical five-second G4 clip identified above. Its hash matched before
and after FFmpeg remuxed its video track to FLV in memory. Independent parsing
found 154 structurally complete FLV tags (153 video tags, including 151 media
packets), zero stream IDs, nondecreasing timestamps, zero composition offsets
and a maximum video tag of 768,751 bytes. FFmpeg was a laboratory remux oracle,
not a production dependency.

The isolated simulated-camera HTTP recording trial failed with the generic
`camera media failed` result before publishing a fragment; the cause is not
yet established. It used executable SHA-256
`938bdbf6f90248a2dceee62076a589b9176779990c78f583bd8ba5506bb72adb`,
synthetic discovery and HTTP settings, and made no physical-camera request.
The incomplete private trial state remains in mode-0700 tmpfs under
`/dev/shm/fss-unifi-http-high-20261115-01` on `ts1`, outside the fallback
retention policy; its deletion-denying trace is
`/data/tmp/fss-unifi-http-high-20261115-01/fixture.trace`.

A payload-free diagnostic build, strict-remote job `j-30109207290184337`,
repeated the unmodified FLV replay and identified `recording:Timeline`. The
source MP4's first two decode times were 0 and 1 tick at 90 kHz; the FLV
remux rounded both to zero milliseconds. Subsequent FLV sample intervals were
33 or 34 milliseconds. The recorder intentionally refuses equal timestamps;
this does not establish that the live camera sends equal timestamps.

A diagnostic replay changed only the second remuxed sample's FLV timestamp
from 0 to 1 millisecond. It then refused `Mux(UnsupportedFormat)` in the
default AVC mode. Structural inspection found that both keyframe samples
carried in-band SPS and PPS before the IDR; the other 149 samples carried
non-IDR slices. A final replay used the existing explicit `avc3` in-band
mode and that same one-millisecond timestamp adjustment. It published and
reopened one native Rust video fragment and decoded one frame
at 2688 x 1512. It does not claim that the entire five-second source was
archived. Discovery, camera HTTP responses and serializer effect were
simulated; the source was a historical Scrypted-originated clip, without
audio, and the video timestamps were modified for this diagnostic. No
physical camera setting changed. These tests do not establish a live direct
stream, camera identity, A/V synchronization or continuous recording.

The diagnostic executable SHA-256 was
`1ab946547f524f4d474f88568542db6417603bfcc364b2d14dc9d289d74ded52`;
the video HTTP runner source was
`d1567c4431f5d0747bc4066b3656c84f81275423dae3dcd8bad2fd0c959ce664`.
Trial traces are retained under `/data/tmp/fss-unifi-http-high-20261115-02`
through `-05` on `ts1`. Their private tmpfs trial states remain under
`/dev/shm/fss-unifi-http-high-20261115-02` through `-05`, outside the
fallback retention policy. The exact mode that passed is a caller-selected
laboratory profile, not automated camera-format detection.

The final diagnostic binary passed 13/13 isolated recording cases, three
checkpoint comparisons, three checkpoint/journal cases and three simulated
live observations; the dimension-mismatch case checked the new payload-free
refusal category. It also passed 7/7 synthetic A/V cases and both audio-option
refusals. Those fixture traces are retained under
`/data/tmp/fss-unifi-http-high-20261115-06` and recorded 29 and 15 denied
unlink attempts respectively. A separate check confirmed that the diagnostic
FLV retiming changes exactly one byte and refuses to apply the adjustment
twice. The shared recording fixture SHA-256 was
`f0e510951a04993a0f755c4de102e25e5982834def3247e49fcaa9f7420a06ce`;
the private-input fixture was
`447693242cb07ef477a43325fcab11a4ddf51b185915de3f8ba8a3befdf3c0d7`.
After these runs, the existing Scrypted recorder remained active with seven
restarts and six MP4 files modified in the preceding five minutes.

### Automatic conservative AVC policy for HTTP recording (2026-11-15)

The automatic pinned HTTP recording paths now select the fixed-configuration
`avc3` writer before reading video, for both video-only and A/V recording.
This is a conservative policy, not detection of future stream content: the
initial configuration arrives before later keyframes can reveal whether they
will repeat its parameter sets. The writer accepts either no repeated sets or
byte-identical in-band sets and still refuses changed sets. This changes the
experimental output sample-entry format from `avc1` to `avc3`; compatibility
with external playback clients has not been qualified. It does not authorize
or perform a physical-camera write, provide continuous recording or change
the explicit AAC-source requirement.

Strict-remote job `j-30109207290184338` built the change on `ts1`; executable
SHA-256 was `3da6dd0dac3358408e2669471f93aaaf8065ff456db14a1b44ea6f33d249fd46`.
An isolated simulated-camera replay of the historical G4 clip above passed
without the previous manual `--lab-inband-avc` flag and decoded one 2688 x
1512 frame after reopening the Rust archive. It still used FFmpeg remuxing,
the one-millisecond second-sample adjustment, a simulated HTTP camera,
synthetic discovery and no audio. The private archive remains under
`/dev/shm/fss-unifi-auto-avc-20261115-01` on `ts1` and is outside fallback
retention.

Eight A/V synthetic scenarios passed, including streams with no repeated
parameter sets, byte-identical repeated sets, and altered repeated SPS. The
altered case refused `Mux(UnsupportedFormat)` with the committed simulated
effect still marked for reconciliation. Both AAC option-refusal cases passed.
The separate recording regression passed 13/13 scenarios, three checkpoint
comparisons, three checkpoint/journal cases and three simulated observations.
The video, A/V and real-clip traces under
`/data/tmp/fss-unifi-auto-avc-20261115-01` recorded respectively 29, 16 and
four denied unlink attempts. The shared and A/V fixture SHA-256 values were
`f872c0564c3538d778a2c522bf4f6ef81839ae88333a009351af479152ad8133` and
`f15ee380737e712ab6d5d4fb40db6172be934955d552ba3883e7fb2137a59104`.
The existing recorder remained active with seven restarts and six files
modified in the preceding five minutes. Synthetic audio was not decoded.
These results do not establish direct
physical-camera control, live A/V, playback interoperability, unattended
recording, recovery or retention.

### Opt-in same-session restore after HTTP recording (2026-11-15)

The bounded HTTP video and A/V laboratory commands now accept
`--lab-http-restore-after`. Before any forward write, this mode refuses a
selected prior serializer that is absent or neither an object nor null. After
successful archive readback and an anchored post-start observation, it takes
another fresh full serializer observation. A separate restore plan must match
the original request and leave the other tracks unchanged; a separate
operation is prepared and committed before dispatch. The command then requires
the restore response and a fresh full readback matching the original baseline.
The two effect permits remain unresolved, including after matching readback;
the readback is held in memory, not anchored as a separate post-restore
checkpoint. None of these claims prove physical identity or camera behavior.

This is a bounded same-session experiment, not unattended recovery. It only
attempts restore after a successful recording path. Earlier start, capture,
archive or observation failures do not trigger automatic restoration; a
partial restore, timeout, lost session or crash still requires reconciliation.
It does not settle either effect, restore shared audio, eliminate the race
between revalidation and the camera write, or establish that null or object
updates restore an actual device. No physical camera was written by these
tests, and earlier physical effects remain indeterminate.

Strict-remote job `j-30109207290184339` built the command on `ts1`;
the executable SHA-256 was
`09eeb894eab0f7c4cb57ce492a4711e76640dc890563b21f4ac0242da7ed3f46`.
Seven isolated synthetic restore cases passed: null and object prior values,
an ignored restore, an unrelated-track change, interrupted restore response,
missing prior value, and an A/V restore. The fixture checks that the changed
track and missing baseline do not dispatch a restore, that ignored or
interrupted restore does not report success, and that both dispatched effects
remain unresolved. A separate argument-refusal case passed. An earlier run
passed the seven cases but failed that argument check because its input hit
discovery validation first; the input was corrected and the entire suite was
rerun. The fixture and shared helper SHA-256 values were
`062f3282506b28def1781f5de6690a4b823c8d884c633ca13db632d31025a600` and
`6facd988b02a5d092b3657dc69ed3981120322b29bee0600a4cec7d1d976cfc7`.

The same binary passed 13/13 synthetic recording scenarios, three checkpoint
comparisons, three checkpoint/journal cases, three simulated observations,
8/8 A/V scenarios and two AAC option refusals. Deletion-denying traces under
`/data/tmp/fss-unifi-restore-20261115-02` and `-03` on `ts1` recorded 29,
16 and 23 denied unlink attempts for video, A/V and restore respectively.
The existing Scrypted recorder remained active with seven restarts and six
files modified in the preceding five minutes.

### Anchored post-restore observation (2026-11-15)

The opt-in same-session restore now seals its successful final serializer
readback into a third encrypted checkpoint before reporting a matching
restoration observation. A separately invoked
`--compare-http-restored-checkpoints BEFORE RESTORED --owner-authorized`
reopens and authenticates both checkpoints and compares all three serializer
values and the bound forward request. The comparison refuses the same
directory, a byte-identical encrypted artifact, different request or camera
claims, and unequal baseline values. Distinct encrypted artifacts are not
proof of independent observation, freshness, causality, camera identity, or
effect settlement; the root and its pin storage are operator-selected and
share a trust domain. Both camera effects remain unresolved.

Eight synthetic restore scenarios passed, including a blocked final
checkpoint destination after a restore request, and the separate argument
refusal passed. For successful null, object, and A/V cases a separate process
authenticated the final checkpoint and compared it with the baseline; the
same-checkpoint and changed-value comparisons were refused. A copied
checkpoint was also refused, at the earlier namespace-bound pin recovery
step. The first copy test expected a later artifact-identity error and failed
its assertion despite that correct earlier refusal; after accepting either
valid refusal, the entire suite passed. The copied-artifact digest check itself
was not independently reached by that test. A cross-request comparison was
separately refused. This is synthetic process-reopen evidence, not a crash,
power-loss, rollback-protection, or physical-camera test.

Strict-remote job `j-30109207290184341` built the command on `ts1`, executable
SHA-256 `ed83606f3d3a5d2f57dd83fb3b743cab86c4de697c0854b2bd7f4f1adde503c3`.
Its checkpoint module SHA-256 was
`9dd50c2e246fbffa32be60f61653b519c4b5c47c26b526ed31b1ee28c14b19fa`.
The restore and shared fixture SHA-256 values were
`28961ca157c11e4dde82d1d219ad38c00be31d34c20b88b1a81501dc15bfad53` and
`105d5cd8883912e4151d4b38810a93102332ccb38d34eae48b8604785fbaf5b6`.
The same binary passed 13/13 synthetic recording scenarios, three checkpoint
comparisons, three checkpoint/journal cases, three simulated observations,
8/8 A/V scenarios and two AAC option refusals. The video, A/V, restore and
cross-request deletion-denying traces under
`/data/tmp/fss-unifi-restore-20261115-05` and `-06` recorded 29, 16, 27 and
zero denied unlink attempts respectively. The existing recorder was active
with seven restarts and six recent files after the tests.

Restoration still runs only after successful capture and archive readback;
startup, capture, lost-session and crash recovery remain unfinished. The
physical camera's serializer write/restore semantics, shared audio, actual
high-resolution direct stream, continuous capture and retention remain
unqualified. No physical camera setting was changed in these tests.

### Opt-in restore after selected media failures (2026-11-15)

The bounded HTTP video and A/V trials now also attempt the separately
journaled restoration when the opted-in stream reaches EOF or its source
limit, or when recording or FLV framing refuses media. They first abort and
join their owned archive workers and recover the complete driver owners. A
fresh full serializer observation must still match the requested forward
setting and preserve the other tracks; it is encrypted and anchored. The
restore operation takes another fresh observation, then a matching final
readback is separately anchored. An ignored restore, changed unrelated
track, or checkpoint failure remains unresolved. The original recording is
still reported as failed even when a restore readback matches; no media or
effect outcome is silently upgraded to success.

Cancellation, lost authority, generic transport failures, worker failures,
startup/accept refusals, and process crashes do not trigger this automatic
write. A focused classifier test checked cancellation, stopped/audio-pending,
authority refusal and offset-overflow as ineligible, and framing and
recording refusals as eligible. Authority, lease, deadline, private readback
and exact request checks still apply during restoration. These observations
do not prove device identity, causality, physical restore semantics, or
independent effect settlement; shared audio is not restored. The experimental
path remains explicitly opted in with `--lab-http-restore-after`.

Strict-remote build `j-30109207290184342` produced executable SHA-256
`58a59aafb725177ea76690ac382b6ec62d065821b8da7da7fd7ed273e67d7655`.
Fourteen synthetic restore cases passed, including short and malformed video,
short and mismatched-configuration A/V, changed unrelated settings, and an
ignored restore. Successful failure-recovery cases cold-reopened and compared
the final encrypted checkpoint, retained two unresolved effects and still
exited as failed recordings. An additional argument refusal passed. The
shared and restore fixture SHA-256 values were
`2bff4d19d86e5a6252b99a1eabb6cccdad170258789306655af8d456a17679e8` and
`6ce3773b7d769a57468defc886b7601b09a97e029b8c59507b87ce43f243d365`.

The same executable passed 13/13 synthetic recording cases, three checkpoint
comparisons, three checkpoint/journal cases, three simulated observations,
8/8 A/V cases and two AAC option refusals. The classifier test built as
strict-remote job `j-30109207290184343` and passed 1/1 on `ts1`; its test
executable SHA-256 was
`42eb84e742c3998a558d9eed261008e56dd8caa42050cbebc366ab63a154f5e6`.
The newer source differs from the executable-tested runtime source only by
that test module. The restore, video, A/V and classifier deletion-denying
traces under `/data/tmp/fss-unifi-restore-20261115-07` and `-08` recorded
41, 29, 16 and zero denied unlink attempts respectively. The existing
Scrypted recorder remained active with seven restarts and six recent files.
No physical camera was written; real-camera restore, direct A/V, continuous
recording, crash recovery and retention remain unqualified.

### Opt-in restore after a matched-readback listener timeout (2026-11-15)

The bounded HTTP video and A/V trials can now attempt the same anchored
restoration when the listener times out after the forward write received a
matching, target-only serializer readback. They retain the failed startup
owner and its permit, re-read and anchor the forward observation, revalidate
again before a separate restore effect, and anchor a matching final
readback. The recording remains failed and both effects remain unresolved.
This supersedes the earlier statement that every startup/accept refusal was
ineligible: only this specific timeout, with a retained readback and a
possibly written request, was added. An indeterminate write, absent readback,
unconfirmed forward settings, denied listener admission, authority failure,
other accept errors and non-opted-in attempts do not trigger recovery.

Strict-remote build `j-30109207290184344` produced executable SHA-256
`85dcedf3c2a4790b9cfb1008f1f9732b886b9cf1dd094b8be5c6e5bb2530d7d5`.
Twenty synthetic restore scenarios passed, including video and A/V listener
timeouts, changed settings and ignored restore after timeout, an unconfirmed
forward readback and a timeout without opt-in. Successful timeout recovery
still exited as a failed recording and cold-compared its retained baseline
and restored checkpoint. An additional argument refusal passed. Two focused
classifier tests built as job `j-30109207290184345` and passed on `ts1`,
including refusal for authority, admission, missing readback and indeterminate
write; their executable SHA-256 was
`8d4c856e2332a43d8fdd958250084cd95ea7a789c3f723ccc4cc422998485017`.

The same command binary passed 13/13 synthetic recording scenarios, three
checkpoint comparisons, three checkpoint/journal cases, three simulated
observations, 8/8 A/V scenarios and two AAC option refusals. The restore,
video, A/V and classifier deletion-denying traces under
`/data/tmp/fss-unifi-restore-20261115-09` recorded 41, 29, 16 and zero denied
unlink attempts. Fixture SHA-256 values were
`1112cbb28111785c461b7a4c42178335e2994d7b4bee59e662c5848d44a7e932` and
`9990043425a6e6a1075d4704ef67286b86ca1f8aba3ccac406acfe982dc28f7f`.
The existing Scrypted recorder remained active with seven restarts and six
files modified in the preceding five minutes. No physical camera setting was
changed. These tests do not prove actual device restore behavior, identity,
shared-audio safety, independent settlement, crash recovery, continuous
recording or 30-day retention.

### UniFi observations in the normal discovery command (2026-11-15)

The working-tree `fss-discover` command can optionally run the existing
owner-scoped UniFi discovery laboratory probe for each supplied subnet, using
`--unifi-principal` and `--unifi-approval` together with the existing
`--owner-authorized` flag. The approval must identify an existing owner
authorization; the command does not create one. All UniFi scopes are checked
before the general discovery sweep starts. The CLI checks the digest's syntax
and nonzero value, but does not independently verify that it names a retained
authorization. Both one-shot and watch modes emit
separate `fss.unifi_discovery_auto_lab.v1` JSON records, retaining per-interface
results and failure or truncated-window states. A report never establishes
absence, authenticates a camera, enrolls it, or grants a setup effect. The
general discovery record and retained-liveness inputs are unchanged. This is a
discovery bridge, not the requested automatic onboarding or recorder.

Strict remote build job `j-30109207290184348` compiled the `fss-discover`
test binary on `ts1` from the isolated
`fss-unifi-discover-integration-20261115-02` snapshot. RCH omitted source
directories named `coverage`; the two required files were placed separately
in the private remote snapshot and their hashes matched the local snapshot.
The compiled `fss-discover.rs` and `fss-unifi-discover.rs` hashes were
`664a564eabee8cd145341dbb8ed97d9601ebb2980f81ea8673100fa611e013c5`
and `a3e5fbc78c8a3e25ee4e55526b1175ff0c4129e13b458e07c8b385860c5b9da0`.
Under deletion-denying `strace`, 14/14 scoped UniFi discovery tests and 1/1
normal-command authority/scope test passed; both retained traces under
`/data/tmp/fss-unifi-integrated-discovery-20261115-01` were empty. The tests
did not contact a real camera, run an end-to-end discovery sweep, install the
command, or validate native setup, stream capture, continuous recording or
retention. Existing Scrypted and recorder services were not modified.

### UniFi-only main-command discovery against the G4 (2026-11-15)

`fss-discover --unifi-only` now selects only the scoped UniFi observation path;
it skips the other probes and census. It requires the same principal and
approval options, and refuses watch, retained-liveness and other-probe
options rather than silently ignoring them. This remains an opt-in laboratory
discovery path, not automatic camera enrollment or a recorder. The digest is a
caller-supplied authorization claim, not independently verified by the CLI.

Strict-remote `ts1` build job `j-30109207290184349` produced binary SHA-256
`fbe0465f6e9fb6fdd21bee07061fedf8c953aabd75afc13750b3702f693991eb`.
Test-build job `j-30109207290184350` built the same source snapshot; the new
mode refusal test, the authority/scope test and 14 UniFi discovery tests
passed 16/16 under deletion-denying tracing. The three traces under
`/data/tmp/fss-unifi-only-tests-20261115-01` on `ts1` were empty. The edited
main command source SHA-256 was
`9059fb23e2f2c20aff567b0c771832a0026f0080d807382ad9d53bfb58ea1f56`.

One copy of that binary was hash-matched on `trj` and run once using the
existing hash-matched owner discovery authorization and subnet. The completed
three-second window received one datagram and reported one `UVC G4 Instant`
claim at the address in the authorization inventory. It labeled the claim
`identity=unverified` and `setup=unavailable`. The retained syscall trace
contains two local netlink sends for interface enumeration and one IPv4
discovery send to UDP port 10001, with zero denied deletions. The report and
trace remain private under `/data/tmp/fss-unifi-only-20261115-01` on `trj`.
The recorder and original discovery timer were active afterward; the recorder
still reported seven restarts and six fallback MP4 files had been modified in
the previous five minutes. This proves a bounded real-network observation at
the inventory address, not cryptographic device identity, provisioning,
streaming, uninterrupted recording, or safe replay of earlier indeterminate
camera-control effects. No camera login, setting write, or service change was
performed, and the tested binary was not installed as a service.

### Bounded AAC allowance in HTTP-started A/V recording (2026-11-15)

The HTTP-started A/V archive driver can now use the existing explicit finite
`AudioAllowancePolicy` while it owns the live stream and archive workers. At a
quiescent archive boundary it checks task time and authority, reports a renewal
before further media work, debits only the caller-supplied allowance, and
reports exhaustion or worker refusal without polling media. Invalid wait or
context follows the existing driver refusal path. Renewal does not reset the
AAC epoch, retry a failed publication, extend storage capacity or authorize a
camera operation. The bounded experimental HTTP A/V recorder now drives this
path, with a finite allowance of its own.

Strict-remote test-build job `j-30109207290184351` compiled the reference
integration fixture on `ts1`. Its exact checkpointed HTTP A/V test passed 1/1
in an isolated network namespace: an exhausted plan paused, an invalid wait
did not spend its budget, a valid plan renewed, and the fixture subsequently
published and reopened A/V segments. The deletion-denying trace at
`/data/tmp/fss-http-av-allowance-tests-20261115-01/test.trace` records three
denied deletion attempts. The first separate full-recorder fixture run stopped
before discovery because its private network lacked the required `fssdummy`
interface; this is a failed fixture setup, not a passing recorder result.

Strict-remote build job `j-30109207290184354` then built the experimental
recorder, SHA-256
`65469009246e2f70b435ddb4c79800a1fd3d60f6ce0a1e3188a951477a08ed9c`.
With the corrected isolated interface and synthetic camera, eight A/V
scenarios and two option-refusal checks passed. Successful multi-segment
recordings required the renewal output as well as A/V publication. Its trace
at `/data/tmp/fss-http-av-allowance-run-20261115-02/fixture.trace` records
16 denied deletion attempts. The driver, recording-session policy, lab
recorder, and fixture hashes were respectively
`6f2bfd0f8aff5d8405f354476f2bfeabe8a687040bfe156db3cc8d4f46c578a8`,
`24d35b08de4f8743528eb0bae26c5d338a0c68b341b78e88585b15afde971977`,
`137381bbd37d54e84a2ffb8c8a84a5de3195678051785536df63d6a2a4c32b91`, and
`0dd6313cc19a2167856d3f48f485c1eaab500bb8dbea2ba983893801d3ff1c6d`.
No physical camera or service was changed. The Scrypted fallback remained
active with seven restarts and six recently modified MP4 files. This does not
establish direct G4 streaming, storage rollover, service restart, real audio
sync, continuous recording, or 30-day retention.

### HTTP A/V capacity rollover with retained stream custody (2026-11-15)

The HTTP-started A/V archive driver now retains the exact settled predecessor
reported by a before-publication journal-capacity refusal. It reports
`RolloverRequired` and refuses a blind retry while that condition remains.
`RolloverPreflight` pauses the HTTP stream and its separate-source worker,
checks the recorded predecessor binding, and runs the existing custody check
on a task-owned blocking worker. Its successor worker stages, commits, and
replays the confirmed graph using caller-supplied fresh stores. Only a
successfully prepared matching successor reattaches the original pending A/V
segment; the resumed driver arms that segment for its next archive step.
Pre-start recovery restores the original owners and unused supplies; failures
after work starts return the paused stream, exact outcome, and storage owners
for reconciliation. This does not discover or create successor stores, renew
generation authority, reconnect the camera, or establish a retention period.

Strict-remote test-build job `j-30110656841646084` built the exact reference
integration source on `ts1`. In an isolated network namespace the filtered
suite passed 2/2 non-ignored tests, with one private-camera replay ignored.
The success case used a five-record A/V journal, retained a capacity-stopped
segment, checked that blind retry was refused, recovered both unstarted
rollover stages, then switched and reopened three synthetic 2688 x 1512 A/V
segments. The denial case refused the confirmed-graph read and retained the
paused source, pending segment, transition and failure outcome. The trace at
`/data/tmp/fss-http-av-rollover-tests-20261115-03/test.trace` recorded seven
denied deletion attempts. The test executable SHA-256 was
`c5eb936231841f69cdc0a221762343ac4b0c77805a239d9947a4d2a13d8775d5`;
the driver and fixture SHA-256 values were
`3f839140d82778384b07b47ec495199dddc62ba05ef46c04476025f3920ad26b` and
`2f74a4ee5b66203a31de320588cc6ab35b82a04cdde24b07c33f8d4f01ebdc29`.
The recorder on `trj` stayed active with seven restarts and six recent MP4
files. These are synthetic stream and storage results, not proof of a real G4
handoff, independently authenticated camera, unattended generation creation,
crash recovery, gap-free capture, or 30-day retention. No physical camera
setting or service was changed.

### Finite automatic HTTP A/V successor provisioning (2026-11-15)

The HTTP A/V path now has a caller-driven `Managed` owner that plans a finite
series of successor generations, creates the next stores on a task-owned
blocking worker, and continues recording while creation proceeds. At a settled
capacity boundary it pauses media, checks the original archive, switches and
replays the confirmed graph, then reattaches the pending segment. It retains
generation identity and storage/pin-custody inputs, checks created paths and
pin scope against the selected identity, bounds locally retained custody,
and does not silently retry failed creation or rollover admission. Cancellation
requires draining the owned workers. Generation selection is currently an
in-memory plan: callers must retain custody observations, and this owner is
not a crash-restart supervisor or proof of independent storage custody.

The first automatic fixture run published and reopened three segments, but
failed an additional expectation that a standalone-source event would occur
after bootstrap; the source prefix had already been handled in bootstrap.
The fixture was corrected to keep the existing bootstrap source assertion and
not require an additional event. A separate creator-collision case was added.
Strict-remote test-build job `j-30110656841646087` then built the exact final
source on `ts1`. In a private network namespace four non-ignored tests passed:
automatic creation/rollover with three synthetic 2688 x 1512 A/V readbacks,
creator collision retaining its failure and pending segment, denied rollover
replay, and the prior explicit rollover case. One private-camera replay was
ignored. The trace at `/data/tmp/fss-http-av-auto-test-20261115-03/test.trace`
recorded 14 denied deletion attempts. The executable SHA-256 was
`8919cab7adb7ba63340495afecd9d42b20621cbe1e287b0c34ed206ad415df7d`;
the managed owner, archive driver, and test SHA-256 values were respectively
`3031bc8a8e478b99823ca994f2e120122804fa3b5895113d707ebe9323966ad5`,
`cc31baeeebfb0c45a1533aec49c4db9ff5e52f689ee73b1dc629b58fdc2a46db`, and
`cfd555400465cc63af3b1e8e47fd62c087ec909c06bc560b7d99bd13a3d2db08`.
The recorder on `trj` remained active with seven restarts and six recently
modified MP4 files. These checks do not establish live direct camera control,
process-restart recovery, uninterrupted capture, real audio synchronization,
or 30-day retention. No physical camera setting or service was changed.

### Automatic generation provisioning in the HTTP A/V trial command (2026-11-15)

The bounded HTTP A/V trial command now has an opt-in finite automatic-generation
mode. It drives the existing managed owner, reports allowance renewal and
rollover, drains its workers, and retains generation custody with the trial
outcome. Automatic restoration is explicitly refused in this mode; the existing
non-automatic restoration path is unchanged. The generation plan is in memory,
and the journal and pin stores use the same caller-selected parent. This is not
evidence of restart durability or independent storage custody.

Strict-remote build job `j-30110656841646090` rebuilt the final binary after a
copied incremental cache had incorrectly reused an older binary in job
`j-30110656841646089`. The final executable's embedded result string was
checked for `trial_http_av_auto=drained`, and its SHA-256 was
`ba3e4ee20595dbeff2dc6f16bab9b2559bffb3bd5066351a3ed0af4c354af4fd`.
In an isolated network namespace, the final binary passed 9/9 synthetic A/V
scenarios and 4/4 argument-refusal checks. The automatic scenario forced a
rollover and required three A/V publications and readbacks. Its trace at
`/data/tmp/fss-http-av-auto-cmd-run-20261115-02/fixture.trace` recorded 20
denied deletion attempts. The trial command, A/V runner, shared fixture and
A/V fixture SHA-256 values were respectively
`2f0cbeb3f62d11674a9f382cbe4b22dcda81e1cadec59da125b405d32df01e74`,
`b995a96f0ba6d6260345966d4201c9b97951c01342f31b8245057d8709b8d05e`,
`919666ff43d2c85f5efdb106a4b92706e8698353600eb1437d4ca93ed0d128ea`, and
`14b740cdfd11b3b3c786dc8e5a23e57f9d552d0a6736fef7a079ef15f015d50a`.
These results do not establish a direct physical-camera stream, safe physical
handoff or restoration, unattended recording, restart recovery, or retention.
No physical camera setting or existing recorder service was changed.

The same final binary also passed the existing non-automatic restoration
regression in an isolated network namespace: 20/20 synthetic scenarios and
1/1 argument-refusal check. Its retained log and zero exit receipt are at
`/data/tmp/fss-http-av-auto-restore-run-20261115-02` on `ts1`; the trace
records 41 denied deletion attempts. The first run terminated without a
recoverable terminal receipt, so it is not counted. The restoration fixture
SHA-256 was `9990043425a6e6a1075d4704ef67286b86ca1f8aba3ccac406acfe982dc28f7f`
and its shared fixture was the `919666ff...d128ea` version above. These are
simulated restore outcomes with unresolved effects; automatic-generation mode
still refuses restoration and no physical camera restoration is established.

The command fixture now also interrupts the synthetic A/V stream while the
automatic manager owns it. It requires a failed trial with the camera effect
still unresolved, no published-success report, and the previously published
archive root retained. An initial fixture launch failed before executing a
case because its private input directory lacked a Python helper; the helper
was copied from the earlier fixture and the failed launch is not counted.
The corrected isolated run passed 10/10 synthetic A/V scenarios and 4/4
argument-refusal checks, with zero exit and 22 denied deletion attempts. The
log, receipt and trace remain at
`/data/tmp/fss-http-av-auto-cmd-run-20261115-04` on `ts1`. The updated shared
and A/V fixture hashes were
`dc711ddd9ac2837188f904cb2531e1a12bfa823d2cf6da05a39e4596a1b6bd76` and
`03f26140b1007c81bc52c62dfb3b3a34b9d187a3eab359d727b28c14597d4bf9`.
The fallback recorder remained running with seven reported restarts and six
MP4 files modified in the preceding five minutes. This fixture does not prove
crash recovery, real-camera restoration or uninterrupted recording.

### Automatic A/V failure drains recording workers (2026-11-15)

The automatic HTTP A/V trial previously aborted its owner on failure and joined
the generation creator and rollover worker, but did not also join source and
A/V recording workers before returning the retained error. The managed owner
now exposes a recording-worker join, and the trial's automatic failure paths
abort and join these workers while retaining their completion values with the
owner and failure observation. A rollover owner has already paused its source
and retired its A/V worker before admission. These in-memory outcomes do not
provide durable custody after process exit.

The first strict-remote test build, job `j-30110656841646091`, failed because
the transfer excluded two source directories named `coverage`. Their files
were copied into the isolated worker snapshot and hash-matched; the later
test and command builds compiled on `ts1` but their wrappers returned 102
because the Linux executables were intentionally not transferred to macOS.
The binaries were retained and tested on the worker. The initial test run
overflowed the default test-thread stack; with a 32 MiB thread stack, the
initial cancellation case failed because the source worker had already ended
in bootstrap. That failure remains a failure of the initial test. The revised
case cancels an admitted A/V worker, retrieves its completion and transfers the
drained recording owner. The exact test binary listed the revised test name;
it passed that case and the existing automatic-rollover case 2/2 under a
deletion-denying trace at `/data/tmp/fss-http-av-drain-test-20261115-03`.
The trace recorded five denied deletion attempts. The executable SHA-256 was
`8ec74feb055c0d6a4936dc273ab11366226482db2cb34b8cb7241916f7956af0`.

The independently built experimental command passed 10/10 synthetic A/V
scenarios and 4/4 argument-refusal checks, including the interrupted automatic
stream, with zero exit. Its log and trace remain at
`/data/tmp/fss-http-av-drain-cmd-run-20261115-01` on `ts1`; the trace recorded
22 denied deletion attempts. The command binary SHA-256 was
`c7bb33ba88d0f8df8bd07d38f8449112a8404699d1f59646ff6d5ccdf5a55a6f`.
The managed owner, test and trial caller hashes were respectively
`0273d7b2bd0bbe0d82934d9594410c161e2eb0a747225ce8edc196bc7ea7ed41`,
`7c72d744b39450da89059c96c00128e7a50b8b57b073d5390fdacf9cafc5be34`, and
`9501ad1d45d926adf7a6a8277fb10176abf90553223c0862be559273d4832afb`.
The existing recorder remained active with seven reported restarts and six
files modified within five minutes. No physical camera setting was changed;
these tests do not qualify real-camera takeover, crash recovery or retention.

### Guarded restoration after automatic A/V trials (2026-11-15)

The experimental HTTP A/V command now permits restoration after a bounded
automatic-generation trial. A successful trial follows the existing
post-recording observation, restoration and anchored-readback path. For an
early media EOF, limit or eligible media failure, it first cancels and joins
the managed workers, retains their completion and generation custody, and
requires the recording driver to yield its complete parts before requesting
the existing guarded failure restoration. Other automatic errors continue to
require reconciliation without initiating restoration. A successful readback
is still a camera claim; neither serializer effect is independently settled.

Strict-remote job `j-30110656841646095` compiled the command on `ts1`; its
wrapper returned 102 because it declined to transfer a Linux executable to
macOS. The worker binary SHA-256 was
`3b2388ea3c464af07d268578258351513e03284877d666a230fe09495b28c8af`;
its embedded option-refusal string and transferred source hashes were checked.
The isolated simulated-camera fixture passed 13/13 A/V cases and 3/3 option
refusals, including automatic rollover then restoration, early-stream
restoration, and refusal to restore after another track's settings changed.
The log, zero exit receipt and deletion-denying trace are retained at
`/data/tmp/fss-http-av-combined-restore-20261115-01` on `ts1`; the trace
records 30 denied deletion attempts. The trial runner, CLI, shared fixture and
A/V fixture SHA-256 values were respectively
`b2c715a5b38e8cb46777d1f5fe8816b2d9d5546d62bfb64e6e674a6834dac436`,
`5d54718c42d254245835488c8fd44b064add2ac38a6bda6a8fef3897f0058ecf`,
`7527f941c7ae3566829214c7ae2515e712100e79e80b88e051178dbbaefb8cf7`, and
`908a5da7d3a88e2a19346554e74a7142a01f6e54d6eb1338bce59ecc8794d433`.
No physical camera was written. The existing recorder remained active with
seven reported restarts and six files modified within five minutes. This
does not establish real-device restoration, identity, crash recovery,
uninterrupted recording or 30-day retention.

### Physical G4 observation with the automatic-restore build (2026-11-15)

The command binary from the preceding section was copied to `trj` and
hash-matched before two owner-authorized observation-only runs. The first used
automatic certificate-derived selection. It found one candidate matching the
previously network-observed certificate, read two consistent serializer
projections and received a camera claim of video1 at 2688 x 1512 and 30 fps.
It refused comparison with the retained bound checkpoint because the camera or
certificate claim did not match, and stopped before snapshot decoding. The
earlier investigation above had established that this particular checkpoint
uses a MAC/address-derived claim; that earlier comparison does not establish
physical identity.

One follow-up used the sole camera address from the retained discovery report
and its current neighbor-cache MAC for the original claim type. The same
binary completed with `success_no_effect`: the two fresh serializer readings
matched, all three serializer values matched the saved checkpoint, its
proposed stream fields were absent, and Rust decoded an in-memory 640 x 360
snapshot. The pin matched the locally retained certificate. The first attempt
to prepare this follow-up stopped before starting the binary because its
neighbor-cache field selection was wrong; it made no camera request. The two
completed observations used no camera-settings write, and their traces under
`/data/unifi-g4-recorder/fss-auto-restore-observe-20261115-01` recorded zero
deletion attempts. The existing recorder was active afterward with seven
reported restarts and six recently modified files.

These are current network and camera claims: the pin and MAC/address do not
independently authenticate the physical camera. The unchanged serializer
observation does not settle earlier handoff or clock effects, establish direct
high-resolution media delivery, or qualify physical restoration, crash
recovery or retention. The checkpoint and the new observation are from
different sessions, and no claim is made about intervening changes.

### First direct HTTP video trial on the physical G4 (2026-11-15)

The saved discovery report's single camera address refused bounded TCP
connections on ports 554, 8554, 7441 and 7447. This is a point-in-time test
of those ports only; no RTSP request was sent and no general service-absence
claim follows.

The exact previously tested experimental command binary, SHA-256
`3b2388ea3c464af07d268578258351513e03284877d666a230fe09495b28c8af`,
was run once on `trj` against the selected physical camera. The bounded trial
used certificate-pinned discovery, selected the reported high video profile,
bound a separate listener, anchored an encrypted pre-change checkpoint,
requested one video segment with the explicit 16-byte A/V trailer heuristic,
and opted into guarded same-session restoration. The existing Scrypted
recorder was left running. The camera setting was actually written; this was
not an observation-only trial.

The camera's readback matched the requested target track, and the Rust
listener received enough stream bytes to archive an FLV header and a tag with
the structure of 290-byte metadata. The selected framing heuristic then
refused `TrailerPolicyMismatch`, and the trial failed without publishing a
video fragment. The received peer was admitted by its network address, not
independently authenticated at the media socket. The rejected suffix was not
retained after process exit, so this result does not identify the correct
trailer format or prove that a video frame arrived. No image or clip resulted.

The failure path requested restoration; its same-session readback matched
the baseline and a separate encrypted restored checkpoint was anchored. A
cold comparison of the baseline and restored artifacts was consistent. A
fresh, separately logged-in observation then found the current serializer
values unchanged from the restored checkpoint and reported the same high
profile. These readbacks are camera claims, not independent causal proof.
Cold inspection of the retained setup fence reported two committed, unresolved
operations; neither the forward nor restore effect is settled or authorized
for blind retry. The original and restored checkpoints, journals, partial
source archive, log and traces remain private under
`/data/unifi-g4-recorder/fss-http-physical-20261115-01` on `trj`. The trial
trace recorded two denied deletion attempts and the later inspection and
observation traces recorded none. The listener had closed; the existing
recorder remained active with seven restarts and six recently modified MP4s.
This does not establish gap-free fallback recording, shared-audio behavior,
physical device identity, direct video decoding, crash recovery or retention.

### Diagnosing the strict trailer refusal (2026-11-15)

The strict 16-byte A/V-flag policy selected in the physical trial above was a
poor default for that experiment: earlier bounded G4-derived captures had
already shown trailer flags that did not match it. That earlier finding does
not identify the exact bytes rejected by the new physical trial, whose
unparsed suffix was not persisted. The existing `ZeroStreamId` policy is a
conservative structural alternative supported by earlier medium-stream
observations; it still assumes zero stream IDs and does not authenticate a
boundary or establish that the high-profile connection uses the same format.

The packet crate now exposes its existing bounded zero-stream-ID successor
search for diagnostics. After a strict-trailer media refusal and a guarded
failure-restoration attempt, the experimental video command retires the
drained pipeline and reports whether that search finds a structural candidate,
needs more bytes or refuses. It reports candidate trailer length only, never
payload bytes, labels the boundary unverified and notes an unappended source
suffix. The remaining pipeline and worker owners stay attached to the
in-memory failure result; this does not add durable storage for the suffix.
The diagnostic does not select a new framing rule, issue a camera write or
settle an effect.

Strict-remote job `j-30110656841646096` compiled the command on `ts1`; its
wrapper returned 102 because it declined to copy a Linux executable onto
macOS. The worker executable, SHA-256
`76b87afb5f6c50482547224fa744b0958c905ca65e597b51d292e6bb41be9df2`,
contained the new diagnostic. In an isolated network namespace three command
cases passed: strict framing refused a synthetic bad-flag stream, its
restoration path emitted the diagnostic, and the zero-stream-ID policy
published and decoded two synthetic 2688 x 1512 fragments from the same
stream bytes. The trace at `/data/tmp/fss-http-framing-diagnostic-run-20261115-01`
recorded eight denied deletion attempts. A separate isolated regression passed
20/20 synthetic restoration cases and one option refusal; its trace at
`/data/tmp/fss-http-framing-restore-run-20261115-01` recorded 41 denied
deletion attempts. The packet source, trial runner and fixture SHA-256 values
were respectively
`956e542663adacd54d2c1ef24a81e2096051e6311ef6750ba420084320692ff0`,
`f4677f7ed9d094806eb3fc20864dbda62bc9d86b3058ab7b40e3b0ed006c26fb`, and
`824af6e177f0afd4674444765e40e27fb9ffbd3d0d4eaf03833fe698d1f98361`.
No physical camera request was made in these checks. The existing recorder
remained active with seven reported restarts and six recently modified files.
The prior physical trial's two effects remain unresolved; another camera
write must not be inferred from this synthetic result.

### Matching the physical trial's retained metadata to its request (2026-11-15)

The failed physical trial did retain the FLV header and an initial metadata tag
as source objects before the trailer refusal. A bounded independent AMF0
inspection of the hash-matching metadata object found a complete `onMetaData`
object with one top-level stream-name string matching the trial's generated
request name. It did not print the name or source payload. This strengthens
the association between the requested stream and the admitted connection, but
the source object was selected from a local archive by the operator; the
comparison does not authenticate the media peer or prove journal settlement.

The experimental command now also exposes an owner-scoped, read-only Rust
comparison. It reopens and authenticates the encrypted request checkpoint,
reads and hashes the caller-selected source spool object, parses one complete
AMF0 metadata tag, and compares its top-level stream name with the checkpoint's
forward request without printing either. It refuses missing or ambiguous
request names, wrong event or malformed metadata, differing names and missing
or corrupt source objects. It does not prove that the selected object belongs
to the checkpoint's source journal, bind capture time, or settle an effect.

Strict-remote job `j-30110656841646097` compiled on `ts1`; the wrapper returned
102 after refusing to transfer the Linux executable to macOS. The worker and
`trj` binary SHA-256 matched
`779d566bf342607ff80360b3fb09c079b2990cae42c5d64a10f44012ed142632`.
Against the retained physical-trial artifacts the Rust comparison passed; it
also refused an unrelated checkpoint, a non-metadata FLV object, and a missing
digest. These are 1/1 positive and 3/3 negative read-only artifact checks, not
new camera sessions. Their traces under
`/data/unifi-g4-recorder/fss-http-physical-20261115-01` showed zero deletion
attempts. The checkpoint-module and CLI source SHA-256 values were
`f08de2c884ff84b800bf9cda89032187465c3e010b20292a7135298f48d70448` and
`47af6db62579c08e11100eaffea4d90354e34d54fab49c9b4ecaab42f00fb401`.
The recorder remained active with seven restarts and six recently modified
files. The two camera effects remain unresolved, and no camera write was made
for this artifact comparison.

### Stream-name probe before HTTP video recording (2026-11-15)

The real G4 metadata above contained the per-request stream name in an
`onMetaData` event. The HTTP video archive driver now exposes the existing
bounded, non-consuming name probe before recording begins. The experimental
command can opt into that probe with `--lab-http-name-probe` and requires its
existing restoration option. It expects the current trial's generated name,
up to four tags, a 256 KiB prefix and a bounded work/time budget. Matching
metadata allows the normal recorder to consume the retained prefix. A missing,
mismatched, stopped or timed-out probe stops capture, drains the archive
workers and invokes the existing guarded failure-restoration path. A matching
name remains an untrusted connection claim, not authenticated camera identity
or an independently settled camera effect. This option is video-only and is
not automatically enabled for other models or the A/V path.

Strict-remote job `j-30110656841646098` compiled on `ts1`; its wrapper
returned 102 after refusing to copy the Linux executable to macOS. The
executable SHA-256 was
`57a093e6ee8d61d2cb127eccf21ab75c8a6f1f8e008e5cf3a7afcf09ebd95c45`,
and its embedded probe marker was checked. Three isolated simulated-camera
cases passed: a matching initial name followed by two decoded video fragments
and restoration; a mismatched name stopped before video publication and
restored; and an unrelated-track change prevented restoration. One separate
argument test refused name probing without restoration. The first fixture's
trace under `/data/tmp/fss-http-name-probe-run-20261115-01` recorded five
denied deletion attempts. Four existing video, failure-restoration,
zero-stream-ID and automatic A/V scenarios also passed under the trace at
`/data/tmp/fss-http-name-regression-20261115-01`, which recorded 15 denied
attempts. These are simulated peers; the new option was not used to write the
physical G4. The driver, video trial, CLI and fixture source hashes were
respectively
`3056f76915d45bdddc8bd497ff6dc28b08a5bd6cd709ebc6e0e245cc440eeb12`,
`9814bfdc03d41082552baca1d0bd0f07f4c4b5bcf843bbab12d3447aa1d3c828`,
`ead05e8659bffd4a15ab121513cc70ded5bcdc57acd2c7fe943cdde1388b596d`, and
`22f2c27c3434b13568ab72050eb729e6632da466b984174729f601c93b8b5b24`.
The recorder remained active with seven restarts and six recently modified
files. The previous physical effects remain unresolved, and these cases do
not establish a direct video clip, continuous capture, or crash recovery.

### Passive G4 metadata-trailer observation and controlled comparison (2026-11-15)

Two bounded passive captures observed the existing medium-track TCP push on
`trj`; they did not request a new stream or change camera settings. The helper
matched the retained discovery report's camera address and reconstructed TCP
payloads in memory. It synthesized an FLV header and selected a midstream
candidate, so the observations below use structural candidate boundaries,
not authenticated framing or proof of complete capture. No source media was
persisted.

In the first sample, bounded to 20 seconds, a zero-stream-ID conservative walk found 877
candidate tags and 876 adjacent 16-byte candidate trailers. Ten successors
followed metadata, and none of their candidate trailers matched the strict
metadata A/V-flag rule used in the failed physical high-stream trial. In a
separate sample bounded to 12 seconds, five metadata successors each had a 16-byte
candidate trailer and seven zero padding bytes; all five had a flag outside
the strict rule's zero/one assumptions. The successors comprised three video
and two metadata candidates. These observations establish neither the actual
meaning of the flag nor the high-profile stream's trailer format. The passive
helper SHA-256 was
`db0ac13c5f2a8f53a671078c56f0707db4f73f5f53805c288a473bd5cf1cdbd8`.

A separate synthetic fixture constructed a matching `onMetaData` stream-name
claim followed by a 16-byte trailer with an arbitrary nonzero/nonone flag.
With the same bytes, the name probe matched in both cases: strict framing
refused and ran its guarded failure-restoration path; the zero-stream-ID
policy published and decoded two video fragments and restored. Both cases
passed on the previously built `57a093e6...ed95c45` executable, with seven
denied deletion attempts in the trace under
`/data/tmp/fss-g4-metadata-framing-run-20261115-01` on `ts1`. The fixture
SHA-256 was `21c55a3d3ae235cac23ba0930989b4bc8b829cf04be411bb4ba1bc7816c955c4`.
The flag value is synthetic; it is not asserted to equal either passive
sample's unprinted value. The recorder remained active with seven restarts and
six recently modified files. No physical settings request was made here; the
previous physical effects remain unresolved and high-resolution direct video,
peer identity, continuity and retention remain unproved.

### Local source graph and ledger comparison (2026-11-15)

The experimental command now accepts an owner-scoped source-graph comparison.
It inspects the selected source deployment's local ledger without opening the
deployment writer, requires a clean ledger and the expected unknown-time root
revision, and reads a hash-verified canonical source manifest and its two
children. It checks the recorded retention, source generation, first-tag
metadata record and camera claim against the authenticated request checkpoint,
then compares the source tag's stream name to the checkpoint request. Each
comparison uses a drained bounded worker; no source bytes or names are printed.
The checkpoint is reopened through the existing checkpoint recovery machinery,
which may acquire local locks; this is not an atomic filesystem snapshot.

The root is operator-selected. The ledger and graph are local observations,
not independently anchored proof against rollback or substitution. This check
does not reopen or prove membership in the source-intent journal, authenticate
the physical camera, establish capture time, or settle either camera effect.
The archive retains temporary root-publication files, so the command reports
publication state as unverified; it does not remove or ignore those files to
claim a stable published root.

Strict-remote job `j-30110656841646099` compiled on `ts1`; the wrapper returned
102 because it refused to download a Linux binary to macOS. The worker binary
and copy on `trj` had SHA-256
`c722cca4e283cba822b1178a5412cb71a67c97515339447f5db6ae9c09a34f52`.
On an existing simulated-camera archive, the one metadata source root passed;
two nonmatching records, a different request checkpoint, a missing root and a
different deployment were refused (1/1 positive and 5/5 negative cases).
On the retained physical trial, the metadata source root passed and the other
source root was refused (1/1 positive, 1/1 negative). These checks made no
camera request and ran in network-isolated processes. Traces under
`/data/tmp/fss-ledger-comparison-20261115-01` on `ts1` and
`/data/tmp/fss-ledger-physical-20261115-01` on `trj` recorded no deletion
attempts; the latter also recorded no rename attempts. The checkpoint module
and CLI source SHA-256 values were respectively
`6d8fb3fd90aa38c01b21a165a6cd0703b476646f4da51d4f8098eac70c81f330` and
`49e2a55f3a6dd36d5b631127b35e23a6b921c1a5b06d469267c9f1657e314a8f`.
The fallback recorder remained running and six MP4 files had recent
modifications. The earlier camera effects remain unresolved; a matching
source graph does not authorize retrying them or establish direct video.

### Local source-intent history observation (2026-11-15)

The laboratory comparison can additionally inspect the selected archive's
source-intent and source-anchor histories without opening their writer. The
bounded inspector hashes each spool object, checks envelope order and prior
digest links, validates the expected intent scope, retention and unknown-time
markers, replays prepare/confirm pairs, and checks each local keeper target
against the observed intent chain. It requires the selected root to be
confirmed, no pending intent and a keeper caught up to the observed head.
Spool classification is repeated; no lock, migration, repair, replay pin or
effect authority is produced by this history inspector.

The observed heads come from the same storage. The check does not establish
an independently retained minimum, validate the stored namespace against the
present physical directory, exclude rollback or substitution, or guarantee an
atomic snapshot. The older source spools lack a holds directory; inspection
reports that layout without migrating it. The checkpoint portion still uses
its existing local recovery opener. A local history confirmation is not
settlement of the camera's forward or restore operations.

Strict-remote job `j-30110656841646100` compiled on `ts1`; its wrapper returned
102 after declining to copy the Linux executable to macOS. The executable
SHA-256 was `30e8ad522c8211a94f2a7ae3956d037f29dae7c845b7ae952324a68a108ba04e`
on both the worker and `trj`. One synthetic positive passed; a corrupted
intent object, a pending selected intent, and a keeper behind the intent
head were each refused (1/1 positive, 3/3 negative). For the retained G4
artifacts, the metadata root passed the local history, keeper, ledger and
checkpoint-name checks; the non-metadata root was refused before the history
check. Both physical-artifact runs were network-isolated and did not contact
the camera. Their traces under `/data/tmp/fss-local-history-physical-20261115-01`
and the synthetic traces under `/data/tmp/fss-local-history-20261115-01`
recorded no deletion or rename attempts. The local-history module,
checkpoint module and trial CLI SHA-256 values were respectively
`295302e7e8359a7993d4dd2bb41682eba4eefac2b6b263ac2bc89cece688f148`,
`de2ab620bb9d4ba593159d08efec02d4ad384e12cb4190c5ac0e65222d2b8480`, and
`963ef7a19668ef4aecbe46f2f7b40fc7c53b986121aa1e7e115d8e385555bc75`.
The workspace-copy manifest was also checked after including the new module
and local crate dependencies. The fallback recorder remained running with six
recently modified files. Direct high-resolution video, peer identity and
the two camera-effect settlements remain unproved.

### Explicit 16-byte opaque-flag framing (2026-11-15)

The packet framer now has an opt-in `StructuredTrailer16OpaqueFlag` policy,
with new evidence ID 5; the existing policy IDs and defaults are unchanged.
It requires zero FLV stream IDs, exactly 16 trailer bytes, seven zero padding
bytes and a structurally valid successor at that fixed offset. The remaining
trailer bytes, including the previously rejected flag, remain opaque and are
retained in the source record. This is an explicit framing hypothesis, not
authentication or proof that every firmware uses the same format. Refusals
preserve the unconsumed source bytes. The experimental direct trial selects it
only when explicitly passed `--lab-trailer16-opaque`.

On `ts1`, the stream contract executable passed 16/16 ordinary tests (one
private-input test ignored), including all 256 flag values across every split
point of the fixture, embedded false headers, invalid padding, a nonzero first
or successor stream ID, corrupted tag lengths, and retention on refusal. The
metadata contract passed 12/12 ordinary tests (one private-input test ignored),
including refusal of a nonzero first stream ID during the name probe. The
strict-remote build jobs were `j-30110656841646104` and
`j-30110656841646105`; their wrappers returned 102 when they declined to
download Linux executables onto macOS. The corresponding worker executable
SHA-256 values were
`45682dd93fdfc8da76d1513218d30fc376a44331dcbb8b9c4a5eb6f263c467b5` and
`0c1c6e290cccfe970b9199e5ef2a930f3a33d501617c0ee11d736f162bf105e7`.

The first executable was hash-matched on `trj` and explicitly fed a fresh,
12-second passive capture from the existing medium push. It accepted 504
successor candidates, five of them metadata; all 504 observed opaque flag
bytes were outside zero and one. The capture began midstream and used a
synthetic FLV header, and the split points are structural candidates rather
than authenticated boundaries. One contiguous TCP run and one flow were
observed. The reconstructed bytes were held in process memory, including
temporarily on the Mac, and were not written to disk. No camera request or
setting change was made. The earlier executable revision also accepted a
separate passive sample of 506 successors and six metadata successors.

The final trial binary was compiled on `ts1` in strict-remote job
`j-30110656841646106` (wrapper exit 102 after the same foreign-artifact
refusal), SHA-256
`9e32b2529c8a8b709e24cad63b52e39c60caf1cfed96693966f7f0a4a31bfb16`.
Three isolated simulated-camera HTTP cases passed: the new opaque-flag path
matched the requested name and archived/decoded two synthetic 2688 x 1512
fragments with restoration readback; the strict flag policy refused its
nonbinary metadata flag; and the existing conservative name-probe case
passed. The trace at `/data/tmp/fss-opaque-http-20261115-02/trace` recorded
12 denied deletion attempts; packet and passive traces recorded none. The
stream source, stream test, metadata test, trial CLI and fixture SHA-256 values
were respectively
`600fe8988b6b46036625cd5690c0c7c16e83ed21354c8dda35edc86ee029cc71`,
`92ec88021b7cb83a0f8b4ffa1a2fcd2bf661f68c76b19d3fc1c437037f3bf1a0`,
`32279d93231095e43af9f7ac6a978e376ca61c83bc6527d2a86486454ae209cb`,
`0fc03d685965f0c9d8c4f4aae20b40f85920774bf833ae7051108835011f23e8`, and
`6790af7a8360ccc62aa49c7d5e915b0d361be9355238387022fbb8db786b06c6`.
The fallback recorder remained running with six recent files. This result
does not qualify the physical high-profile stream, settle the earlier camera
effects, prove identity or continuity, or permit removing Scrypted and Docker.

### Stream-name probe before A/V bootstrap (2026-11-15)

The HTTP A/V bootstrap now exposes the existing bounded, non-consuming
stream-name probe before it consumes audio or video. The laboratory command
can use `--lab-http-name-probe` with either video-only or A/V capture, provided
guarded restoration is also enabled. It compares the connection's metadata
name to the per-request name. Matching retains the original prefix for normal
A/V processing; a mismatch, timeout or refusal stops bootstrap, drains the
source worker and attempts the guarded failure restoration. The probe owner,
buffered source, checkpoint and worker results remain in custody on failure.
The same probe applies before both ordinary and automatically rolled-over A/V
recording. A name is a connection claim, not authenticated camera identity or
proof that a camera effect settled.

Strict-remote job `j-30110656841646107` compiled the command on `ts1`; the
wrapper returned 102 after refusing to download a Linux binary to macOS. The
worker executable SHA-256 was
`4fa6fa66b954489a2419e76fe4e1f3e366d6f0882d8028cc657054dfdcd28508`.
Five isolated simulated-camera cases passed: matching-name A/V capture;
matching-name A/V with the 16-byte opaque-flag policy; a wrong name with
restoration readback; a wrong name with a changed other track, which refused
restoration; and matching-name automatic A/V rollover. The wrong-name cases
published no A/V roots. Four existing simulated regressions passed for
supplied AAC, in-band AAC, automatic rollover/restoration and video-only
opaque-flag capture. A separate argument check refused A/V name probing
without restoration before creating any effect paths. Audio payloads and
camera responses in these tests were synthetic and no physical camera was
contacted. The traces under `/data/tmp/fss-av-name-run-20261115-01` and
`/data/tmp/fss-av-name-regression-20261115-01` recorded 28 deletion attempts,
all denied.

The A/V bootstrap, A/V startup, trial A/V runner, trial CLI and fixture source
SHA-256 values were respectively
`87bac65bd267026fb878b52f9ab6f358cee8014250b125085d98d8aa43b017bb`,
`43a7034373425a6b3959e17706f8bbd09e2a7ffdf352c194ee977348c1c2fdcb`,
`b4a748b6f57771d0a79a5604c39275d20461743de53c83990f386296ba34d69c`,
`639a0473a734f098034d2c7451be507a230d74782840c6133480341ad24729a2`, and
`ce02bde3af3d07557a13be5318bc13e4dd93ae52bb808d492de7f0634f61517e`.
The fixture and all compiled source hashes matched their local counterparts;
the workspace-copy manifest passed. The fallback recorder remained running
with six recently modified files. This does not prove real-camera A/V, audio
synchronization, crash recovery, 30-day retention or safe resolution of the
prior physical effects.

### Forward and restore effect precondition comparison (2026-11-15)

The setup-fence inspector can now compare three retained checkpoints with the
same recovered effect journal. It authenticates and compares the original
baseline, a matching forward observation and the separate restored baseline;
matches the forward request and precondition to the start effect; and checks
that the restore effect's recorded precondition equals the forward observation
checkpoint's precondition. The restored values must equal the baseline. A
separate request digest for the restore is not reconstructed or matched, and
the inspector does not mutate the journal or settle either effect. The
checkpoint opener still acquires its existing local locks; the retained root
and identity claims remain operator-selected and not independently verified.

Strict-remote job `j-30110656841646108` compiled on `ts1`; the wrapper returned
102 after rejecting transfer of a Linux executable to macOS. The worker and
`trj` binary SHA-256 values matched
`836496e8541f3a8621f2c9a796e8eafceb4710bf2906f03b8b17d5a2164afaa5`.
Four isolated simulated-camera cases passed: successful video restoration,
restoration after a target-only precondition change, successful A/V name
probe and restoration, and failed A/V name probe with restoration. The
comparison accepted the three matching cases and refused the deliberately
changed restore precondition; duplicate checkpoint paths were refused. The
fixture trace at `/data/tmp/fss-restore-bind-run-20261115-01/trace` recorded
12 deletion attempts, all denied.

Against the retained physical G4 trial artifacts, the forward request and
preconditions matched the first journal entry; the observed preconditions
matched the restore entry; and the restored checkpoint matched the baseline.
Both effects remain `Committed` and unresolved. This check ran in a network
namespace with no camera request; its trace under
`/data/tmp/fss-restore-bind-physical-20261115-01` recorded no deletion or
rename attempts. The fence inspector, CLI and fixture source SHA-256 values
were respectively
`11817bbc5dd6ad7d6fb4728571d2f86a9fb64f909984a1ee65e604d25a128589`,
`8f6b7b68cfc268ebbb26d09b7399e9d47e9844705c2a7d0187cf6294e7b88e90`, and
`e8e10027c171d011786075b8cf4c38cec5c877dd8c03651cc793ff6d15086c9c`.
The existing recorder remained running with six recent files. This is not
independent device authentication, proof of causal execution, restore-request
binding, effect settlement or authority for another camera write.

### Exact restore-request digest comparison (2026-11-15)

The encrypted-checkpoint API now compares a reconstructed restore request
against an expected journal digest. It first requires the supplied original
peer, stream settings, generation and framing to reproduce the checkpoint's
forward request digest and channel. It then reconstructs the restore body
from the retained prior serializer using the same encoder as live restore
planning, and compares its digest with the journal entry. Fresh inspection
authority is required; private settings and stream names are not printed. The
result is an equality comparison only, not camera authentication, proof of
dispatch, effect settlement or a retry grant.

The experimental fence inspector adds an owner-scoped mode that performs this
comparison after the prior forward, observation and restored-checkpoint checks.
Its peer address is supplied by the operator; it is not itself authenticated.
Strict-remote job `j-30110656841646109` compiled on `ts1`; its wrapper
returned 102 after declining the Linux-to-macOS executable transfer. The worker
and `trj` executable SHA-256 values matched
`442f0b71d1d0fec4b135af3c899dc01852141cc9ae007c1283655734045c2439`.
Five isolated simulated-camera cases passed, covering null and object
baselines, changed restore preconditions, and matching and mismatched A/V
stream names. The exact request comparison accepted the matching cases and
refused a wrong peer. Its fixture trace under
`/data/tmp/fss-restore-request-run-20261115-01` recorded 16 deletion attempts,
all denied.

Using the one candidate from the retained owner-selected discovery report,
the comparison against the physical G4 trial artifacts matched the restored
baseline to the committed restore-request digest; a different peer was
refused. The forward request and restore precondition also matched their
entries. Both effects remain `Committed` and unresolved. These artifact checks
ran in a network namespace and contacted no camera; their traces under
`/data/tmp/fss-restore-request-physical-20261115-01` recorded no deletion or
rename attempts. The fallback recorder remained running with six recently
modified files. These results do not establish an independently authenticated
camera, causal execution, uninterrupted recording or permission to retry a
camera effect.

The focused `fss-reference` library test build was attempted as strict-remote
job `j-30110656841646110` and failed with 21 compile errors, including missing
binary test fixtures on the worker snapshot. Fourteen locally present missing
fixtures were copied create-only into that isolated worker snapshot and
hash-matched. The additional `ts1` executable build timed out in the scheduler
with `RCH-I001`/exit 103 before admission. A distinct library test build on
`hz2`, with 16 excluded fixture and source files prepopulated and hash-matched,
then compiled successfully in strict-remote job `j-30110656841646112`; its
wrapper returned 102 after declining the Linux executable transfer to macOS.
The worker test binary SHA-256 was
`8ac3daa1c7698337de187eb59335f0e3aeb58dd8ca823789f5dfdb9019dddad3`.
The focused encrypted-checkpoint test passed 1/1, including matching and
wrong restore digests, wrong peer and denied inspection. Two restore-planning
regressions also passed 2/2, including null, absent and object baselines and
unrelated-track drift. These three tests ran in isolated network namespaces;
their traces under `/data/tmp/fss-restore-unit-20261115-01` on `hz2` recorded
no deletion attempts. The simulated and physical-artifact checks above used
the previously identified trial executable; a subsequent source change only
expands its usage text.

The retained DER camera certificate was separately inspected on `trj`: its
issuer and subject were equal, and its signature verified under its own public
key. No subject, serial, key or private media was printed or stored by this
check, and no camera was contacted. A valid self-signature is not independent
evidence of manufacturer issuance or physical-device identity; no external
manufacturer chain was checked. The certificate pin remains a local
trust-on-first-use claim, so this observation does not settle either effect.

### Fallback archive interval and capacity observation (2026-11-15)

A read-only inventory of the fallback directory on `trj` found 11,285 MP4
files whose filename timestamps spanned 2026-11-05 22:09:18 UTC through
2026-11-15 12:24:04 UTC, totaling approximately 51.48 GiB. The files are not
uniformly present over that entire span: sorting the filename timestamps found
six adjacent differences over 90 seconds, including a roughly 41.8-hour
difference early in the history. This inventory does not establish that the
recorder was intended to run during that early interval.

For the 24 hours preceding the inventory, there were 1,440 files totaling
approximately 6.24 GiB. One adjacent filename-timestamp difference exceeded
90 seconds: 94 seconds between 2026-11-14 17:30:56 UTC and 17:32:30 UTC.
FFprobe reported durations of approximately 35.0 and 64.9 seconds for those
two respective files; both reported 1280 x 720 video. This is a concrete
continuity concern of approximately 59 seconds if the filename timestamps
represent segment start times. Filename times and container duration are not
independent camera capture timestamps, however, so this alone does not prove
the exact length or cause of missing scene coverage. Neither file was fully
decoded in this check. A separate redacted, read-only service journal check
found that the recorder exited at 17:31:41 UTC, a subsequent startup reported
a timeout at 17:32:16 UTC, and recording was reported started at 17:32:29 UTC.
This supports a process-restart interruption near the filename interval; the
underlying reason for the initial exit was not established. A further
whitelist-only classification of that journal window found the FFmpeg worker
reported exit code 0 at 17:31:39 UTC, followed by the controller reporting
exit code 0 and the supervising service exiting unsuccessfully. A clean worker
exit did not imply uninterrupted recording. The startup timeout occurred on
the following service attempt, before the later successful start.

At the same time `/bulk` reported approximately 3,253 GiB available. A
straight-line projection of the most recent day's 6.24 GiB gives about
187 GiB for 30 days at the same rate; usage can change, this space is shared,
and this calculation does not prove retention or reserve capacity. The
fallback archive timer was scheduled, the recorder service was active with
seven systemd restarts since its counter began, and six archive files had
been modified within five minutes. The recorder container was running with
zero container restarts since its own start. These separate counters are not
interchangeable. No camera request, setting change, archive mutation, or
service restart was performed for this inventory.

The gap is a reminder that the first-party recorder needs observable coverage
gaps and bounded reconnection in addition to 30-day retention; an active
process or a fresh file is not evidence of uninterrupted capture. It does not
settle the earlier camera effects or qualify direct Rust recording.

The entire HTTP stream unit-test namespace was subsequently run in a network
namespace on `hz2` using the previously compiled test executable
`8ac3daa1c7698337de187eb59335f0e3aeb58dd8ca823789f5dfdb9019dddad3`.
All 8/8 selected tests passed, including the private-key-file reopen, link and
permission refusals; request binding; readback; and restoration cases. The
worker's `http_stream.rs` and `checkpoint.rs` hashes still matched their local
counterparts. The test trace at
`/data/tmp/fss-http-stream-fullunit-20261115-01/trace` recorded no deletion
attempts. This is a bounded unit-test result, not reconnect, physical-camera,
continuous-recording, or full-suite qualification.

### Halted HTTP A/V manager admission (2026-11-15)

The managed HTTP A/V recorder now checks its recording driver's halted state
before planning or admitting another archive-generation creator. It reports
the existing `Halted` decision while retaining any previously admitted creator
for explicit join and reconciliation. This does not claim quiescence, retry
the camera, establish a coverage interval, or implement reconnection.

The new synthetic-camera integration case reaches source EOF after a completed
rollover, transfers that rollover's custody to the caller, and verifies that
two further manager steps return `Halted` without consuming a still-available
generation or creating a worker. The focused case passed 1/1; five existing
checkpointed A/V startup, rollover, collision, denial and cancellation cases
passed 5/5, with the private-input case ignored. The first focused invocation
overflowed the default test-thread stack; the successful runs used
`RUST_MIN_STACK=33554432`. Tests used an isolated network namespace with only
loopback brought up; they did not contact the physical camera. The three traces
under `/data/tmp/fss-http-eof-regression-20261115-01` on `ts1` recorded 22
deletion attempts, all denied.

The first strict-remote build, job `j-30110656841646113`, failed because the
worker snapshot omitted a source file. The omitted coverage source and three
binary fixtures were supplied create-only and hash-matched. Strict-remote job
`j-30110656841646114` compiled the revised integration test successfully on
`ts1`; its wrapper returned 102 after declining the Linux-to-macOS executable
transfer. The worker test executable SHA-256 was
`33d02f199685a398e03b0daec86548a1ed32f39cbe10c3daccce8e0e58b84a14`.
The source and test hashes matched the local workspace. The fallback recorder
was running and six archive files were modified within five minutes. Native
physical-camera capture, identity, effect settlement, reconnection, continuity
and 30-day retention remain unqualified.

### HTTP A/V unfinished-source retirement (2026-11-15)

A stopped, drained HTTP A/V archive owner can now prepare its retained
pipeline tail for the existing ordered source-retirement driver. The handoff
retains the committed camera effect, serializer readback, A/V worker, any
unoffered first segment and rollover state separately. It refuses before
retiring the pipeline if source work is armed, the source worker is not idle,
the A/V worker has an unjoined or armed attempt, the prefix is not accounted
for, or the camera or source claim differs from the connected pipeline. A
range-planning or tail-driver refusal returns the owners at that stage. The
handoff itself performs no I/O and does not convert an unfinished GOP into a
completed video fragment, establish capture time, or settle the camera effect.

The simulated HTTP EOF case now also verifies armed-source and mismatched
camera-claim refusal, then publishes each remaining tail range through the
source worker and reads it back in order against the exact synthetic wire
bytes. It passed 1/1. Five checkpointed A/V startup, rollover, collision,
denial and cancellation regressions passed 5/5; the private camera-derived
input case was ignored. Both runs used isolated loopback-only network
namespaces and `RUST_MIN_STACK=33554432`, and their traces under
`/data/tmp/fss-http-tail-test-20261115-01` on `ts1` recorded 21 deletion
attempts, all denied.

Strict-remote build `j-30110656841646115` compiled successfully on `ts1`;
the wrapper returned 102 because it refused the Linux executable transfer to
macOS. The test executable SHA-256 was
`06e9ee42217556cdbe798370b0170aa8025b7af709072108361532eb2a87dce1`, and
the changed source and fixture hashes matched the worker snapshot. The
fallback had six files modified in the preceding five minutes. This is a
caller-driven archival building block, not an automatically invoked service,
physical-camera tail test, proof of gap-free video, or authority to retry an
unresolved camera effect.

### Bounded tail publication on HTTP A/V EOF (2026-11-15)

The initial version of the experimental HTTP A/V command invoked the source-tail handoff on
EOF or its configured input limit, in both ordinary and automatic-generation
recording. It made at most 256 tail-driver decisions under a ten-second
deadline. Each accepted source completion remained retained; if the tail could
not finish, the command requested cancellation, joined any active attempt, and
retained the returned owners and outcomes for reconciliation. It then followed
the existing optional guarded serializer-restoration path. The later revision
below changes the deadline, decision ceiling and restoration order.

Six synthetic-camera process scenarios passed: ordinary and automatic early
EOF, the same two cases with guarded restoration, automatic early EOF with
other-track drift that refused restoration, and normal automatic rollover.
The four early-EOF cases required a nonzero published tail count, and the
fixture continued to check the relevant unresolved effect-journal states.
These process tests assert publication reports; byte-for-byte source readback
was separately exercised by the preceding lower-level retirement test. All
traffic was confined to a private network namespace. The trace at
`/data/tmp/fss-http-tail-auto-test-20261115-01/trace` on `ts1` recorded 19
deletion attempts, all denied.

Strict-remote build `j-30110656841646116` compiled the command successfully on
`ts1`; the wrapper returned 102 after refusing Linux-to-macOS executable
transfer. The worker executable SHA-256 was
`fbc5e49d59ce25ceb4d932fb725269d4706546897cb2c50a0b0a68834571cf09`.
The command source, fixture source, and archive-owner source matched their
local hashes. The existing fallback had six files modified in the preceding
five minutes. This is still a bounded experimental command, not an unattended
native recorder, physical-camera test, continuity proof, or 30-day retention
qualification.

### Long HTTP A/V tails and restore ordering (2026-11-15)

An independent read-only inspection of four earlier synthetic EOF cases
reopened the source root records after their trial processes exited. It checked
the root checksums, manifest and child hashes, source metadata offsets, and
the matching synthetic wire bytes. Each case had two valid source roots,
including a rooted 12,055-byte unfinished suffix. This checks local object
graphs, not the effect journal's independent custody or physical-camera data.

A new synthetic fixture retains 120 extra AAC records after the last video
boundary. The prior ten-second implementation failed this fixture; 31 source
roots were present across about 10.7 seconds when the case ended. Completing
this tail also requires more than the fixed 256 decisions; the failed run did
not independently isolate the two limits.

The experimental command now derives its decision ceiling from the number of
retained records, reserves event space before polling, and allows a 90-second
tail-publication deadline. When guarded restoration is requested after EOF,
it attempts restoration before starting that longer archival window. Timeout,
allocation failure, and source refusal remain incomplete outcomes; an active
attempt is cancelled and joined, and its owners and observations remain in
memory for reconciliation. The join can outlive the deadline, and the command
does not provide crash-durable recovery for unarchived in-memory bytes.

Six isolated synthetic-camera scenarios passed: ordinary and automatic long
tails, ordinary and automatic guarded restoration, refusal on changed other
track, and normal automatic rollover. The two long-tail cases each produced
122 verified source roots. A separate read-only verifier checked checksums,
object hashes, metadata offsets and wire equality after process exit; each
contained 121 contiguous unfinished or unframed records reaching the end of
the 26,565-byte synthetic stream. The ordinary case's root timestamps spanned
about 51.2 seconds under deletion-denying tracing. The fixture also checked
that guarded restoration was reported before tail publication and that camera
effects remained unresolved. The combined old and new traces under
`/data/tmp/fss-http-tail-old-long-test-20261115-01` and
`/data/tmp/fss-http-tail-bounded-test-20261115-01` recorded 291 deletion
attempts, all denied.

Strict-remote build `j-30110656841646118` compiled the command on `ts1`; the
wrapper returned 102 after refusing the Linux-to-macOS executable transfer.
The worker executable SHA-256 was
`963d0a795c3bd64d58b2ec20e2e9691e529b6e82945a3d73b4db37656f2f0a70`.
The independent verifier on `ts1` had SHA-256
`425be8451b4263806728e40182cde9cd12706f1f396f240eb527f88a435cdf87`.
The fallback still had six recently modified files. None of these results
qualifies continuous native recording, reconnect, physical identity, effect
settlement, or 30-day retention.

### Experimental source-tail batches and staged recovery (2026-11-15)

Profiling the earlier synthetic long-tail trial on `ts1` showed why reducing
the number of rooted publications matters. The whole traced trial made 4,998
completed `fsync` calls totaling about 48.1 seconds and 123 `fdatasync` calls
totaling about 1.18 seconds. Its 122 source-root timestamps spanned 51.6
seconds. A repeat using lower-overhead seccomp tracing spanned 34.1 seconds.
These are instrumented whole-trial observations, not untraced production
latency or a claim that every sync belonged to the tail. The traces under
`/data/tmp/fss-http-tail-profile-test-20261115-01` and
`/data/tmp/fss-http-tail-seccomp-test-20261115-01` denied deletion attempts.

A bounded experimental batch now preserves a contiguous prefix of original
records, including each record's bytes, offsets, disposition and framing
claims, under one unknown-time root. The caller retains its original plan.
Current read authority is checked for ledgered and staged reads. A fully
staged pending batch can be reopened against its journal and independent
keeper, revalidated, and reconstructed as the exact same publication
candidate; altered recovered payload is refused.

The focused integration test passed after publishing and reading a synthetic
batch, interrupting a second publication after staging, reopening its on-disk
journal and keeper, checking denied access and payload tampering, and
republishing the same candidate. Two nearby source-record regression tests
also passed, for 3/3 focused tests total. They ran on `ovh-b` in separate
network namespaces with deletion-denying tracing; the three traces under
`/data/tmp/fss-source-batch-test-20261115-02` show three attempted deletions,
all denied. Strict-remote build `j-30110656841646124` compiled successfully;
the wrapper returned 102 because it refused to transfer a Linux executable
to macOS. The worker executable SHA-256 was
`2096eed4f0928abc695b4513acf77833cca06360a6775ceaa621cd63f0c546f6`;
the five changed source and test files matched the local build snapshot.
The fallback had six recently modified files after these tests.

At this point it was an explicitly caller-driven archival building block;
the later revision below adds an opt-in worker and experimental-command path.

### Batching in the experimental HTTP A/V tail driver (2026-11-15)

The retirement driver can now opt in to bounded batch transfer. It reserves
space before taking original records, returns them in order if the source
worker refuses the offer, and transfers custody to the existing
cancellation-drained archive worker. The worker prepares and publishes the
batch inside its admitted blocking task. Until a confirmed success, an
unstarted, refused, cancelled, or uncertain attempt retains its originals;
uncertain outcomes still require reconciliation. Oversized individual
records fall back to the existing single-record route. The experimental HTTP
A/V command opts in with a 256-record, 1 MiB bound; other callers retain their
existing single-record behavior unless they explicitly enable batching.

Four focused synthetic integration tests passed: normal batch publication
and wire readback, admission refusal and authorized retry, cancellation
before start with exact source custody, and cancellation after task admission
with a drained outcome and accounted source bytes. The last test does not
prove that the blocking closure had reached a particular in-flight kill point.
Separately, six synthetic camera process scenarios passed, including ordinary
and automatic long tails, both guarded restoration modes, refusal on changed
other-track settings, and normal automatic rollover. An independent read-only
verifier reopened each long trial after process exit, checked root and object
hashes, decoded batch metadata, and matched each item to the synthetic wire.
Each trial retained 121 contiguous unfinished or unframed source records in
one batch root; each source archive had two roots overall. The previous
single-record trial had 121 tail roots, but these measurements do not by
themselves establish a comparable end-to-end latency or throughput gain.

Strict-remote builds `j-30110656841646146` and `j-30110656841646145` compiled
the trial and test binary on `ovh-b`; both wrappers returned 102 when they
refused to transfer Linux executables to macOS. The executable SHA-256 values
were `ff2f5d08f0fc3b95bc2c4aa7134a596e0e4685415e95aa43035494551c6a72c0`
and `d3c322cd57878fc38e86915fa5b89ee6c2616b4a23ef9b8c8e56a071cb1ebab4`,
respectively. The independent verifier SHA-256 was
`edb057faa653fa442b4e067c66d8768e37decd221e21a48ce43b540f35a0ea80`.
The changed worker, driver, batch, trial and fixture source hashes matched
the remote inputs. Network namespaces isolated the tests; their three traces
under `/data/tmp/fss-batched-tail-camera-test-20261115-03` and
`/data/tmp/fss-source-batch-test-20261115-02` recorded 37 deletion attempts,
all denied. The existing fallback still had six recently modified files.

`rustfmt --check` passed for the new source-batch module. The targeted
`fss-reference` library Clippy run did not pass: after removing an `expect`
introduced in this batch change, the rerun reported 30 denied `expect_used`
errors in other existing crate code and 911 warnings. The denied errors did
not name the batch module, source worker, or retirement driver. This is an
open crate-wide lint gate, not a release qualification.

This is an experimental command, not an unattended native recording service
or a physical-camera test. Unstaged originals are still in memory. At this
revision, batch replay across source-journal rollover was not implemented; the
later revision below adds it. These tests do not qualify crash recovery at
every publication step, camera effect settlement, uninterrupted capture, or
30-day retention.

### Exact source-batch replay after journal rollover (2026-11-15)

The existing rollover replay now recognizes a ledgered single-source root or
source-batch root from the verified manifest. Both paths use the same current
read and retention authority, retained-switch and journal checks, and exact
root binding. A batch is reconstructed from validated original payload and
metadata, its camera claim must match the caller's claim, and success still
requires an `AlreadyLedgered` receipt before the replay fence is cleared.
Malformed or unauthorized reads are refused; they do not cause a trial write
under another graph type. The camera claim remains unverified identity.

One synthetic test published a batch, committed a rollover, closed and
reopened both journal pairs and the switch, and replayed the exact root. It
checked denied read, wrong camera claim, denied retention, the preserved replay
fence on refusal, the already-ledgered receipt, and every recovered record
against the original synthetic wire. It then published a subsequent source
and exercised the existing chained-rollover recovery. A separate original
single-source rollover regression passed. Three archive-reader regressions
also passed: staged batch recovery, video-only archive readback, and A/V
archive readback; the last deliberately catches two simulated staging panics.
These five tests ran on `ovh-b` in isolated network namespaces. Their traces
under `/data/tmp/fss-source-batch-rollover-test-20261115-01` recorded 35
deletion attempts, all denied.

Strict-remote builds `j-30110656841646149` and `j-30110656841646150` compiled
the respective test binaries on `ovh-b`; each wrapper returned 102 after
declining Linux-to-macOS executable transfer. The test-binary SHA-256 values
were `b255ec27105d5238dc4d20f4b06d8fbfd7f90d1c90cd9ce0287f099b04733519`
and `725e326f17285adb4755f18c6f06ec716b3017feedec91f85e6be404a6dff0ca`.
The changed archive, rollover, and test source hashes matched the worker
snapshot. The existing fallback had six files modified within five minutes.

This replay is a caller-driven recovery primitive, not automatic service
restart, independent keeper custody, or proof of physical-camera identity.
Original bytes not yet durably staged can still be lost on a process crash;
the earlier camera effects remain unresolved, and continuity and 30-day
retention have not been qualified.

### Current Rust A/V path with fresh passive camera-derived media (2026-11-15)

The existing medium-track push was still observable on `trj` without a camera
request or setting change. A bounded passive TCP capture supplied a fresh
sample to the current checkpointed HTTP A/V test on `ts1`; the HTTP camera,
discovery and controller responses in that test were simulated. The test
archived and read back 150 H.264 samples and 77 AAC frames, and Rust decoded a
1280 x 720 video frame. A separate FFprobe/FFmpeg check counted the same
tracks and decoded both to a null sink without reported errors. Audio was not
played. The private mode-0600 readback clip remains under the mode-0700 tmpfs
directory `/dev/shm/fss-unifi-current-av-20261115-03` on `ts1`; this
diagnostic data is outside the fallback retention policy.

The capture began midstream. Its FLV header, initial AVC configuration tag,
and chosen starting boundary were synthesized. AVC configuration came from a
closed fallback file and matched in observations before and after capture;
its connection epoch was not proved. The AAC-LC 16 kHz mono configuration was
the prior relay observation supplied as an unverified hypothesis. The source
identity, physical capture time and A/V synchronization were not independently
established. Of two preceding fresh-sample attempts, one reported a generic
bootstrap failure and the other reported an ingress failure. The test's
configured network budget was below the larger selected input; selecting a
later 878,826-byte sample, bounded around two observed keyframes, passed. The
samples were different and the exact causes of the earlier failures were not
independently established.

Strict-remote build `j-30110656841646152` compiled the test binary on `ovh-b`;
the wrapper returned 102 after rejecting transfer of the Linux binary to
macOS. The binary was copied create-only to `ts1`, and both copies matched
SHA-256 `79152fc1c20d98e14e80afb1302c18c1627e9ed9becba6c4e76148f9e3a36485`.
The archive, source-batch and test source hashes matched the current workspace.
The successful private helper, passive capture helper and configuration helper
SHA-256 values were respectively
`af1d86b8bd97de891a7ec0cb9bfe42a14d3aa8ed4b9a812e2b428b2fd65494f6`,
`db0ac13c5f2a8f53a671078c56f0707db4f73f5f53805c288a473bd5cf1cdbd8`, and
`28f9642ce81a163925e03f555d3669ef0eba8aa8a30b7dd96d4f6069c2f14734`.
The isolated replay trace at `/data/tmp/fss-unifi-current-av-20261115-03`
recorded two deletion attempts, both denied. Six fallback MP4 files had been
modified within five minutes after the test.

This is fresh camera-derived media processed by the native Rust pipeline,
not a native connection to the camera or proof that Scrypted and Docker can
be removed. It does not settle the earlier camera effects or establish
uninterrupted capture, direct onboarding, or 30-day retention.

The current experimental recorder command was also exercised with a separate
fresh passive medium-stream sample. In an isolated network namespace, a
simulated discovery and HTTP camera fed the bounded sample to the actual
command. It archived 150 video samples and 77 AAC frames, read the archive
back, and decoded a 1280 x 720 video frame in Rust. This particular command
run did not independently decode its audio. Its 683,450-byte replay used the
same synthetic-header, selected-keyframe and unverified configuration
assumptions described above; this sample and the preceding independently
decoded test sample were distinct. The private archive remains under
`/dev/shm/fss-unifi-current-cli-20261115-01` on `ts1`, outside the fallback
retention policy.

Strict-remote build `j-30110656841646151` compiled this command on `ts1`;
its wrapper returned 102 after declining Linux-to-macOS executable transfer.
The worker executable SHA-256 was
`fdeee6eefade2fab0466b7bce4e04a95c1326e76726efe9e390cb6ae6a6a0bc3`;
the current command runner, archive source and fixture hashes matched their
worker snapshots. The private orchestration helper SHA-256 was
`6f3d17b1a4bd222aa7b87a4955503c75743a58fa9a1be061cad76732a0217555`.
Its deletion-denying trace at `/data/tmp/fss-unifi-current-cli-20261115-01`
recorded two attempts, both denied. The fallback had six recently modified
files afterward. This test still used Scrypted's existing camera connection
as the passive data source and a simulated controller; it does not authorize
a new physical write, settle earlier effects, or qualify a standalone service.

### Camera-derived sample beyond the old private-test budget (2026-11-15)

A further fresh passive sample reproduced a specific input-boundary failure:
the old private test returned `Ingress(Source(BudgetExhausted))` while trying
to read a 1,048,576-byte selected input. Its two selected keyframes spanned
1,025,973 bytes, exceeding the test's 1,000,000-byte network budget before
accounting for conservative read reservations. This establishes the failure
for that run, not the exact causes of the two earlier separate failures.
The physical camera received no request or setting change.

The explicitly ignored, owner-supplied checkpointed A/V test now accepts at
most 8 MiB of input and has a finite 16 MiB network allowance, while its
normal synthetic scenarios retain their prior limits. Its private framer and
connection bound were raised to 8 MiB as well. A synthetic ordinary-start
regression passed, and an 8 MiB-plus input was explicitly refused before test
setup; its test process exited 101 as expected for the negative case.

A separate fresh 1,100,090-byte passive sample then passed the updated private
test. Rust archived and read back 150 H.264 samples and 77 AAC frames and
decoded a 1280 x 720 frame; an independent FFprobe/FFmpeg check counted and
decoded both tracks to a null sink without reported errors. Audio was not
played. The mode-0600 readback is in the mode-0700 tmpfs directory
`/dev/shm/fss-unifi-current-av-20261115-05` on `ts1`, outside the fallback
retention policy. As above, the setup peer and FLV start were simulated,
the AVC configuration was taken from a separate stable fallback file, AAC
configuration was supplied as a historical unverified hypothesis, and source
identity, capture time and synchronization remain unproven.

Strict-remote build `j-30110656841646153` compiled the test executable on
`ts1`; its wrapper returned 102 after refusing Linux-to-macOS transfer. The
worker binary SHA-256 was
`f48b9a27245e247f6217af654b00ca3ff24beee9bdce724ba6e5def7bb903119`,
and the test source matched the workspace at
`b751fdac42e8298418b6c66e2b903d00ec161711da59cb3bf6eefae6dabd2991`.
The budget probe and larger-sample helper SHA-256 values were respectively
`f72e89424359935c9cee1ddf6809442f874223b8840980096707d02e0952ddfd`
and `a6222f2dfdf846b97649031b5d4a9d997ea77661a31e1d2e3af3a44489d73494`.
The budget-probe trace recorded one denied deletion attempt; the three
private-sample and boundary-test traces under
`/data/tmp/fss-unifi-current-av-20261115-05` and
`/data/tmp/fss-unifi-private-limit-test-20261115-01` recorded six, all denied.
The fallback still had six recently modified files afterward. This adjusts a
diagnostic test, not production limits, and it does not establish a standalone
native camera connection, unattended recording, or 30-day retention.

### Retaining source tail after network-budget exhaustion (2026-11-15)

The experimental HTTP A/V recorder now classifies an ingress network-budget
exhaustion as a stop for which retirement may be attempted, alongside EOF and
the connection byte limit. The caller stops admission, joins workers, and
requires the existing retirement validation before publishing the retained
tail. This classification does not authorize a camera write, settle an
outstanding physical effect, or promise that a failed archive publication was
durable. The automatic and non-automatic lab paths both request tail retention;
budget exhaustion alone does not make camera restoration eligible.

An isolated synthetic-camera test exhausted the actual task's network ledger
after bootstrap, observed the exact ingress `BudgetExhausted` result, drained
the workers, published the remaining source records in bounded batches, and
read the batch bytes and offsets back against the original synthetic wire. It
passed 1/1; the existing EOF batch-retirement regression also passed 1/1. A
cancellation event was explicitly excluded from the new classification. The
two traces under `/data/tmp/fss-http-av-budget-tail-20261115-01` on `ts1`
recorded eight attempted deletions, all denied. These tests ran in separate
network namespaces and made no physical-camera request.

Strict-remote test build `j-30110656841646154` completed on `ts1`; the RCH
wrapper returned 102 after rejecting the Linux executable for the Mac. The
worker test binary SHA-256 was
`e613f242d060e97022b2ffa01e3c7f40d989874005ce0889f7ac6e303ba7dd07`.
The worker and workspace source hashes matched for the archive driver
(`b780c911d2276edba003dca2aa781c37837a32d6618753c34b8c516e58d738b5`),
the integration test
(`f621b5135f4e1fe900a2c446288c16dbdd867863d1dae322ea057f4098a0d7fa`),
and lab command
(`8f6bce6b7c18b5c688a4fb8b2fea7a70648bde6207a67b02c9358c43894ab1c0`).
Six fallback files had been modified in the preceding five minutes.

Strict-remote lab build `j-30110656841646155` also completed on `ts1` with
the same RCH 102 artifact-transfer refusal; the worker command SHA-256 was
`2431dc41a204b046194656bf32a1ce60a4b405678ad60bc3e69574d01a0004ef`.
Six isolated command-level synthetic regression cases passed: ordinary and
automatic long-tail stops, ordinary and automatic restoration after a short
stream, automatic restoration drift refusal, and normal automatic completion.
Their deletion-denying trace under `/data/tmp/fss-av-budget-tail-cases-20261115-01`
recorded 19 deletion attempts, all denied; its 24 other lines are child-exit
signals. These cases did not inject network-budget exhaustion into the command.
The fallback again had six files modified within five minutes afterward.

This evidence covers an already-started synthetic archive driver; the actual
lab command's budget-exhaustion branch, bootstrap exhaustion, process crashes,
camera handoff, uninterrupted recording, and 30-day retention remain unproved.
The network allowance is finite and is not automatically renewed. Physical
camera effects remain unresolved, and the Scrypted fallback is still required.

### Command-level network-budget failure injection (2026-11-15)

The experimental A/V command accepts the explicit laboratory-only
`--lab-exhaust-network-after-bootstrap` option. It spends the remaining
network allowance only after a successful A/V bootstrap, so the ordinary and
automatic paths can exercise the real task-ledger exhaustion branch. The
option is refused outside laboratory HTTP A/V recording. Actual ingress
exhaustion also emits a payload-free diagnostic; the new flag is not enabled
by default and does not renew an allowance.

In an isolated synthetic network, both the ordinary and automatic commands
reported the injected exhaustion, archived a nonempty original-source tail,
and stopped with the effect unresolved. The fixture enabled restoration and
verified that the synthetic camera received no follow-up request after the
stop. Its separate EOF regression also passed. The first injected run failed
an existing fixture assertion requiring more than 85 tail records: an
exhausted input need not receive that many records. The assertion was narrowed
for this injected case to require a nonempty published tail; it still requires
more than 85 for the unexhausted long-tail EOF case. The earlier driver test
independently checked published tail bytes and offsets against the synthetic
wire; these command cases check publication and control flow, not a second
byte-for-byte readback.

The broader A/V fixture then passed 20/20 synthetic scenarios and 5/5 argument
refusals, including both exhaustion modes and refusal of the flag in video-only
mode. These tests did not contact the physical camera. Traces for the first
failed run, focused rerun, and broader suite under
`/data/tmp/fss-av-network-budget-{command-20261115-01,command-20261115-02,full-20261115-01}`
on `ts1` recorded 3, 9, and 53 deletion attempts respectively; all were
denied. Strict-remote build `j-30110656841646158` completed on `ts1` while
its wrapper returned 102 after rejecting the Linux executable for macOS. The
worker executable SHA-256 was
`c4b734837d55b16ab1002594ac25336aa96cdd3d364f49645c9a24c08ec289fe`;
the four modified lab source and fixture files matched the workspace. The
fallback recorder was active with six recently modified files afterward.

This fault-injection result does not prove bootstrap failure recovery, recovery
after a process crash, real-camera handoff, autonomous continuous recording,
or retention. It does not resolve either prior physical camera effect.

### Bootstrap collector and source-tail separation (2026-11-15)

An incomplete A/V bootstrap can hold original configuration records or an
entire first segment in its collector, separately from the pipeline's
unfinished tail. The startup owner now offers a stopped, drained retirement
transition that retains the collector, A/V resources, camera readback, and
unsettled effect separately while validating and attaching the pipeline tail
to the existing source-archive worker. Refusals return the affected owners.
It does not persist the collector or imply complete stream custody.

An isolated synthetic-camera integration test exhausted the real task's
network allowance immediately after a bootstrap input was retained. It
observed the exact network-budget refusal, checked that an armed source
cannot retire, verified the collector's original video configuration against
the synthetic wire, and archived and read back the pipeline tail byte-for-byte
and offset-for-offset. The bootstrap and existing post-bootstrap exhaustion
tests each passed 1/1 on `ts1` in isolated networks. Strict-remote test build
`j-30110656841646159` completed on `ts1`; RCH returned 102 because it refused
to transfer the Linux executable to macOS. The worker binary SHA-256 was
`7405ffe6747418e356f49d9347e5fe0373319e238873389e0730acba489ece03`.
Worker source hashes matched the workspace for the startup driver
(`54cae847331e51ee5dc16d1e8a904506e757c41246c750af26a6bbca424070c2`),
bootstrap driver (`0d1ed37de5866dc3d24e8cb0e14c703ce93512c5a08200d5f0a65c80ae334f24`),
and integration test (`ad9e52403015b36d904b6eb16206d5ac288a5eaef1d93dfdc0c57a771a43ea23`).
The two deletion-denying traces under `/data/tmp/fss-av-bootstrap-budget-driver-20261115-01`
recorded five attempts, all denied. A separate EOF regression passed 1/1 and
its trace recorded five additional denied deletion attempts. The first command
build was refused after waiting for a source lock, and a subsequent `ts1`
build request timed out in the scheduler queue. An alternate source-only
snapshot was staged on `ovh-b` with media and credential filenames excluded;
the command-level build and synthetic trial were then run as described below.

The alternate strict-remote build `j-30110656841646168` completed on `ovh-b`;
RCH returned 102 after refusing to transfer the Linux executable to macOS.
The executable was staged create-only through a local path to `ts1`, and all
three copies matched SHA-256
`4dbed952942d479bd4a552da628d832a0f1dde33573ffeba4dcce08ab47f16e8`.
The worker's startup source and lab command sources matched the workspace, as
did the synthetic fixture on `ts1`. In a network namespace, the full command
passed the injected bootstrap exhaustion case and the post-bootstrap
exhaustion regression. The fixture verified nonempty tail publication,
reported volatile collector custody, and observed no follow-up settings
request with failure restoration enabled. Two argument-refusal checks also
passed without creating effect paths. The broader isolated A/V fixture passed
21/21 synthetic scenarios and 6/6 argument-refusals, including both exhaustion
stages and the conflicting-stage refusal. The focused and broader command
traces on `ts1` under `/data/tmp/fss-av-bootstrap-budget-command-20261115-01`
and `/data/tmp/fss-av-bootstrap-budget-full-20261115-01` recorded 5 and 55
deletion attempts respectively, all denied. The fallback recorder was active
with six files modified within five minutes after the tests.

Collector-held records are still volatile across process exit: only the
separately returned pipeline tail can be published by this transition. This
does not qualify complete startup recovery, continuous recording, physical
camera handoff, or effect settlement.

### Archiving bootstrap collector source copies (2026-11-15)

The preceding collector-volatility limitation is partially addressed for
successful startup retirement. The collector exposes its retained original
video configuration, in-band audio configuration when present, and source
records in an unpublished first segment. Supplied AAC bytes and copied
lookahead witnesses are excluded. Retirement validates their offsets against
received bytes and the held pipeline tail, makes bounded exact copies without
consuming the collector, and attaches them to the source archival plan.
Overlaps or allocation failures refuse with the collector and plan still
owned. Batching stops at a gap; separate roots do not assert that missing
ranges were retained or that coverage was uninterrupted.

The `BootstrapCopy` source disposition is encoded as value 5 in the existing
source and source-batch metadata and is read back by the updated decoder.
Older decoders that do not know this value will reject these records; this
change does not establish cross-version reader compatibility. Successful
publication reports `copies_published` only after all planned attempts drain;
on refusal, cancellation, or incomplete publication the collector remains
volatile and must be retained or recovered separately. A prepared plan is not
a publication receipt, and neither copies nor receipts settle the effect.

Six targeted synthetic tests passed: gap and overlap handling; inclusion of a
first segment without its lookahead witnesses; in-band AAC configuration
selection; bootstrap exhaustion with source readback; post-bootstrap exhaustion;
and existing source-batch archival and readback. The bootstrap integration
read back the copied configuration and pipeline tail with exact bytes, offsets,
and dispositions. In the full synthetic command, a separately archived
pre-roll record created a gap; the collector copy and subsequent tail were
published as two roots, with no follow-up camera request. The post-bootstrap
regression passed, as did the broader 21/21 A/V scenarios and 6/6 option
refusals. The command tests checked publication and root separation; the
byte-for-byte readback was performed by the Rust integration test.

Strict-remote test builds `j-30110656841646172` and `j-30110656841646174`
and command build `j-30110656841646173` completed on `ovh-b`; each wrapper
returned 102 after refusing the Linux-to-macOS artifact transfer. The command
binary matched on `ovh-b`, the local staging location, and `ts1` at SHA-256
`82ff7ba7a0b12fc0dda51198da0b5e333f4eb03c775adb969f175a004411815a`.
The recording test binary after the AAC test was added was
`78c78e9da383dc815f0b31ea98e8894c6b3981aa6b7d8397cde7151bf59bb258`, and
the HTTP dispatch test binary was
`5d7830e737904d1241944364b675d9b1096867a94ac3058ce3d502187348ec66`.
Worker and workspace hashes matched for the changed retirement driver,
recording test, command, and command fixture. A prior test build failed on a
test-only borrow error; it was fixed before these passes. The synthetic worker
traces recorded eight attempted deletions, all denied; the focused and broad
command traces recorded seven and 57 respectively, all denied. No physical
camera request or private camera media was involved. The fallback recorder
remained active with six recently modified files.

This is a bounded failure path, not an autonomous recorder. It does not prove
publication across a process crash, independently authenticate the physical
camera, reconcile prior effects, establish direct camera capture or safe
handoff, or verify continuous 30-day retention.

### Camera-local 1.2 login compatibility (2026-11-15)

The separate [cuckoo management client](https://github.com/rjmotion/cuckoo/blob/2e18666e9d9998b31d908e3a8f1d9ebb658c467f/manage.py)
describes a G5 PTZ using `/api/1.2/login`, a `TOKEN` cookie, and an effectful
`POST /api/1.2/manage`. On the owner-selected G4, bounded observation instead
received `authId` on 1.2 login; that cookie supported a 200 JSON status read
on `/api/1.1/status`. An authenticated `GET /api/1.2/manage` returned 405
with an empty body; an unauthenticated `OPTIONS` returned 200 without an
`Allow` header. These responses do not establish whether management POST is
supported or safe. No management POST or settings write was issued. Pin
comparison preceded each credential or cookie transmission; the pin was
previously network-observed and is not independent physical identity. The
login sessions' expiry is unknown. Redacted reports are retained under the
existing private physical-trial directory on `trj`.

The Rust camera session and metered HTTP owner now allow an explicit 1.2 login
route while retaining 1.1 as the default. The accepted session cookie remains
`authId` only; a `TOKEN`-only response fences the session and is not an
implementation of the G5 profile. Interrupted writes retain the existing
fencing behavior. Strict-remote job `j-30110656841646176` compiled both test
binaries on `ts1`; RCH returned 102 after refusing the Linux-to-macOS artifact
transfer. The worker binaries passed the full camera API suite (16/16) and
the owned loopback HTTP test (1/1), including the new 1.2 route and status
request, in isolated network namespaces with filesystem deletions denied.
These tests used synthetic peers and do not settle any prior camera effect or
establish direct streaming, safe takeover, or continuous recording.

The opt-in laboratory `live_snapshot_probe --api-1.2-login` also compiled on
`ovh-b` as strict-remote job `j-30110656841646177`. RCH returned 102 only after
declining the Linux executable transfer to macOS. The executable's SHA-256
was `eb6ca346779529a27156ac72cae1e59bc0965209afffc773f395dcab04791ee3`;
worker, temporary staging copy, and `trj` copy matched. The worker's camera
API, HTTP owner, and probe sources matched the workspace hashes. The exact
binary ran once against the one previously authorized G4 address on `trj`:
it reported TLS 1.3, matched the previously observed pin, logged in through
1.2, read status, and decoded a 640 x 360 snapshot in memory. No image was
persisted, and the filesystem trace recorded no deletion calls. The fallback
recorder remained active with six files modified in the last five minutes.
This is a real-camera login, status, and snapshot observation through the
experimental scoped TLS laboratory, not a production deployment, independent
identity proof, management write, full-resolution stream, settled physical
effect, continuous coverage, or 30-day retention proof. Login may leave a
session of unknown expiry.

### Journal-bound management 1.2 dispatch (2026-11-15)

The camera handoff owner now supports an explicitly constructed 1.2
management plan. It sends a single private IPv4 WSS destination and a
caller-provided 32-byte token encoded as hexadecimal in the management JSON.
The caller must supply fresh cryptographic entropy; rejecting the all-zero
value does not establish randomness. The request identity binds the peer,
session generation, destination, port and token digest. The plan and body
omit the token from `Debug` and perform best-effort clearing on drop. The
existing journaled effect, current precondition, one-use permit and per-write
authority checks apply; a partial write remains indeterminate. The ordinary
1.1 settings route and its request identities remain unchanged.

This is a low-level, opt-in mechanism informed by the separately observed
[cuckoo G5 management request](https://github.com/rjmotion/cuckoo/blob/2e18666e9d9998b31d908e3a8f1d9ebb658c467f/manage.py).
It is not yet integrated into automated setup, does not verify the returned
camera hello or token, and does not provide a complete restoration plan. The
previous-address preview is address-only. G4 management POST support is not
established, and no physical camera request was made for this change. This
must not be used to evade the still-unresolved previous camera effects.

Strict-remote job `j-30110656841646179` compiled the plan and dispatch tests
on `ts1`; the wrapper returned 102 after declining the Linux-to-macOS
artifact transfer. Workspace and worker source hashes matched. The plan suite
passed 6/6, including changes in token or port and invalid inputs. The full
dispatch suite passed 22/22 runnable cases with six explicitly ignored cases
requiring an isolated private-interface address; both new 1.2 cases passed.
They checked exact method, path, cookie, length and JSON, a mismatched token
permit, denied authority and an indeterminate partial write. These are
synthetic peers. The tests ran in isolated network namespaces with deletion
denied: one attempted deletion was denied, and the dispatch traces recorded
none. The fallback recorder remained active with six recently modified files.
Neither a local write nor an HTTP response proves camera association, safe
takeover, full-resolution capture, uninterrupted recording or retention.

### Listener-bound management setup and hello correlation (2026-11-15)

An explicitly configured setup trace can now select the 1.2 login and
management route when a separately admitted controller listener is already
bound. The existing listener, status, lease, approval and journal checks still
apply. This mode refuses a same-address shortcut because the address alone
does not establish the requested listener or adoption token. After an admitted
peer is accepted, the accept trace can bind a controller's hello check to the
exact committed management-request digest before any controller message is
observed. A missing, malformed or different `adoptionCode` closes that
controller state; a match is retained as a request-bound peer claim. Parsed
JSON while the check is pending and the decoded token receive best-effort
clearing; the underlying received bytes and other parser copies are not
guaranteed cleared. The caller must supply a fresh, cryptographically random
token. A matching claim does not authenticate the physical device, prove
dispatch or prevent replay, and it does not settle the committed effect.

Strict-remote build `j-30110656841646184` completed on `ts1`; its wrapper
returned 102 after rejecting the Linux artifact transfer to macOS. Worker and
workspace source hashes matched. In isolated network namespaces the plan and
hello suite passed 7/7, the controller regression suite passed 32/32, and the
handoff dispatch suite passed 22/22 normally runnable tests plus 7/7
interface-dependent tests when explicitly enabled with an isolated private
loopback address. The new synthetic setup case covers discovery, 1.2 login,
journaled dispatch, a separate admitted TCP accept, and the controller's
in-memory hello claim linked to the permit. It does not exercise a real
WebSocket or physical camera. Token absence, mismatch, invalid form and a
malformed hello version were also checked. One filesystem deletion attempt
was denied and the other final test traces showed none.

An earlier synthetic integration run failed its final journal assertion: the
fixture still treated this new mode as a pre-effect refusal. The assertion
was corrected; an initial rebuild reused a stale executable after source
synchronization, so the test source was retimestamped and the final binary
was rebuilt and rerun successfully. No camera request or private camera media
was involved. The fallback recorder remained active with six recently modified
files. The earlier physical effects remain unresolved; this work does not
establish real-device management compatibility, independent peer identity,
direct high-resolution capture, safe restoration, continuity or retention.

### Management hello over scoped TLS and WebSocket (2026-11-15)

The experimental setup-to-upgrade wrapper now installs the management hello
binding automatically after the selected setup has accepted a connection and
before any controller WebSocket message is observed. If the binding cannot be
matched to the retained committed request, the wrapper refuses. The opt-in
`--lab-management-v12` trial requires pinned automatic setup, an anchored
journal, a persistent fence, and content-length framing. It obtains a fresh
32-byte token from a separately scoped, drained entropy lease; the token is
not an argument, logged value, or TLS entropy. This is a laboratory path,
not production admission or authority to bypass previous effect obligations.

In a private network namespace, a synthetic camera exercised the actual
setup HTTP, journaled management request, TLS 1.3 and WebSocket upgrade. A
matching hello token led to a synthetic 2688 x 1512 video stream; Rust
published three segments across two generations, read back the archive and
decoded five frames. With a different token, the connection closed without a
hello reply and the trial reported `HelloBindingMismatch` (2/2 cases). A
separate option check refused management mode without its required anchored
automatic setup. The legacy automatic-setup fixture passed its 16 reported
synthetic scenarios, including source-pin refusal, unresolved-journal and
restart fencing, concurrent setup fencing, and full-resolution media.

Strict-remote build `j-30110656841646185` compiled the trial on `ts1`;
`j-30110656841646186` compiled the entropy unit test on `ovh-b`. Both wrappers
returned 102 after declining Linux-to-macOS artifact transfer. The worker trial
binary SHA-256 was
`8038c37bdb832aeb2681983a4c1951a1ba35513e60fb01a0e4870c4c78f3354d`.
The focused entropy test passed 1/1, including successful draw, a short pool,
wrong scope, and clearing of the retained pool. Worker and workspace hashes
matched for the changed setup wrapper, entropy source and fixtures. The new
fixture and legacy fixture attempted six and 14 filesystem deletions,
respectively; all were denied. The entropy test trace recorded none.

No physical camera or private camera media was used. The fallback recorder
remained active with six recently modified files. A matching hello is a
correlation claim rather than independent device identity, and the G4's 1.2
management POST compatibility, prior effect settlement, direct full-resolution
capture, safe restoration, uninterrupted recording and 30-day retention are
still unverified.

### Live snapshot-profile and endpoint observations (2026-11-15)

The previously built scoped Rust snapshot probe, SHA-256
`eb6ca346779529a27156ac72cae1e59bc0965209afffc773f395dcab04791ee3`,
was run on `trj` against the single address in the hash-verified existing
owner authorization record. It matched the previously network-observed
certificate before credential transmission, logged in using the protected
credential and API 1.1, read status and settings, and decoded an in-memory
640 x 360 JPEG. The camera reported video1 as 2688 x 1512 at 30 fps, video2
as 1280 x 720 at 30 fps, video3 as 640 x 360 at 15 fps, and its separate
MJPEG snapshot profile as 640 x 360 at 2 fps. These are camera claims in
one session, not proof of the actual high-profile stream or physical device
identity. Filesystem deletion syscalls were denied; no media was persisted.

In a separate bounded pinned session, authenticated `GET /api/1.2/snapshot`,
`GET /api/1.1/snapshot`, and `POST /api/1.1/snapshot` each returned JPEG with
640 x 360 dimensions according to their JPEG headers. Each connection was
pin-checked before credentials or the session cookie were sent. The POST
requested a snapshot, not a settings change. No returned image was saved;
these three responses were not independently decoded, and no conclusion is
drawn about untested endpoints. Login sessions may have unknown expiry.
The upstream UniFi Direct project describes its full-resolution snapshot
path as decoding a keyframe from the high-resolution stream rather than
using the camera's low-resolution MJPEG snapshot:
https://github.com/xuio/scrypted-unifi-direct#how-it-works . This is a
project claim and is consistent with, but does not prove, our observations.

The credential file was root-owned and inaccessible to group and other users.
The earlier setup record in `UNIFI_DIRECT_REFERENCE.md` reports that a
replacement credential was accepted and the factory credential rejected on
2026-11-05. The fresh probe establishes that the existing protected credential
works now; it does not independently retest the factory credential. No macOS
Keychain access was used.

After the probe the fallback service was active, six MP4 files had been
modified in the preceding five minutes, and systemd reported eight restarts.
The previous 24 hours of service logs contained five service exit-code
failures and one timeout; these counts alone do not establish causes, duration
of any recording gap, or the integrity of every segment. No camera setting or
controller was changed. The prior physical effect obligations remain open;
neither profile reporting nor matching a network-observed pin settles them.

### Explicit BT.709 still-image conversion (2026-11-15)

FFprobe reported the hash-checked, historical five-second high-profile G4
verification clip as 2688 x 1512, `yuvj420p`, full range, with BT.709 matrix,
transfer and primaries. This is metadata reported for that saved clip through
the earlier Scrypted-controlled path; it does not prove the color metadata
of a current direct stream or identify the origin of the metadata.

The native still-image conversion now offers explicit BT.709 full- and
limited-range YCbCr-to-RGB matrices alongside the existing BT.601 choices.
Their identities bind the selected matrix and range. Both laboratory command
parsers expose the new choices while retaining `full` and `limited` as their
existing BT.601 aliases. The caller must still select the interpretation:
the H.264 decoder currently skips the VUI color fields, and no automatic
source-derived color selection is claimed.

Strict-remote job `j-30110656841646189` compiled the final integration test
on `ts1`; job `j-30110656841646191` compiled the library unit tests there.
Both wrappers returned 102 when their Linux executables were refused for
macOS artifact transfer; Cargo reported successful builds. The changed source
and test file hashes matched the worker, and the binaries were run on Linux
with networking isolated and filesystem deletion denied. The focused unit
tests passed 2/2, including comparison of 12 synthetic BT.709 vectors against
independently generated FFmpeg RGB values within three levels per component.
The integration tests passed 2/2, with the private-camera test excluded from
that ordinary run. Strict-remote job `j-30110656841646190` checked the scoped
TLS trial command on `ovh-b`; its source hashes matched the workspace.
Strict-remote job `j-30110656841646192` also checked the older TLS lab's
trial command on `ovh-b`, with matching command and still-converter source
hashes. Both checks completed successfully; neither ran a physical camera.

The integration executable, SHA-256
`5442d30c17aa33b32dea071ce194c957026118f521836e7c233951afe4beb11b`,
was copied create-only to `trj` and hash-matched. The explicit private test
then read the hash-checked historical G4 clip locally on `trj`, decoded a
2688 x 1512 frame and produced and decoded a 2688 x 1512 JPEG with the
caller-declared BT.709 full-range conversion (1/1). The test did not contact
the camera or persist the generated image. This confirms a native derivative
of saved, Scrypted-originated footage, not a standalone camera session,
live capture, source-derived automatic color selection, audio, retention or
resolution of the earlier physical effects. The existing fallback was active
with six recently modified files afterward.

### SPS color claims carried through picture decoding (2026-11-15)

The H.264 decoder now preserves an SPS VUI's actual video-format,
full-range and color-description claims on each decoded picture. Missing
fields remain absent and unknown numeric values are retained. The claim is
copied from the SPS attached to that picture rather than from the decoder's
current SPS at output time, so output reordering or later SPS replacement
does not silently apply a newer claim to an older picture. These values are
untrusted stream metadata, not independent proof of camera identity or color.

`Color::from_picture_signal` and `from_picture_signal` can select the still
matrix and range from that picture: matrix 1 selects BT.709, and matrices 5
and 6 select BT.601. An absent color description or unspecified matrix is
reported as missing; an unsupported matrix is refused. No fallback matrix is
silently chosen. The existing archive worker and experimental command still
require an explicit color selection; automatic picture selection is available
as a separate API and is not yet wired into those paths. Container color
metadata and conflicts with SPS metadata are not reconciled by this API.

Strict-remote jobs `j-30110656841646194`, `j-30110656841646196`, and
`j-30110656841646198` compiled the integration, reference-library and H.264
test executables on `ts1`. Cargo reported successful builds; wrappers returned
102 when Linux artifacts were refused for macOS delivery. Relevant source
hashes matched the workspace, and binaries ran on the worker in isolated
network namespaces with filesystem deletions denied. The focused H.264 test
suite passed 14/14, including reordered pictures, SPS replacement while
pictures are buffered, absent descriptions, and truncated SPS data. The still
unit tests passed 3/3, including unsupported and unspecified matrices; the
ordinary still integration tests passed 2/2, with two private tests ignored.
Other attempted worker builds were refused before execution because of worker
headroom or source-namespace admission; those are not test failures or passes.

The integration executable, SHA-256
`4b422e538c7cf5f4ab5e4a5c6d150079b2990a565f68f6a31af2353997d7687e`,
was copied create-only and hash-matched on `trj`. A separate explicit private
test read the same hash-checked historical G4 clip locally. Rust reported SPS
format 5, full range, primaries 1, transfer 1 and matrix 1, then selected
BT.709 full range without a supplied matrix and generated a 2688 x 1512 JPEG
(1/1). No generated image was retained and the camera was not contacted.
This is a source-metadata observation on saved Scrypted-originated footage,
not proof of direct live capture, automatic recorder integration, independent
camera identity, continuity or prior effect settlement. The fallback remained
active and six files were modified within five minutes after the test.

### Source-color policy in the still worker and trial commands (2026-11-15)

The source-color selection can now be used through the region-owned still
worker for both recovered archive clips and confirmed publications. Explicit
BT.601 and BT.709 policies remain available. The two experimental controller
commands accept `--lab-video-still=auto`; this uses each decoded picture's SPS
claim and refuses missing or unsupported matrices. It does not authenticate
that claim or resolve conflicts with container metadata. `Parts.color` now
takes `ColorPolicy`, so callers constructing the worker must select a policy.
Existing source-custody, authority, cancellation and join checks remain in
place. These are laboratory commands, not a deployed recording service.

The new synthetic 160 x 128 fixture is derived from the existing synthetic
baseline with FFmpeg's H.264 metadata filter setting full-range BT.709;
its SHA-256 is
`77be200325e6d524cbffbc635215a811ba7946eee31bbe4c92f2ab71e0926a53`.
No private camera media was used for these tests. Strict-remote jobs
`j-30110656841646201` and `j-30110656841646204` compiled the reference
recording tests and older TLS command fixture on `ts1`; Cargo succeeded but
the wrappers returned 102 after refusing Linux-to-macOS artifact transfer.
Relevant source and synthetic-fixture hashes matched the worker. With
network namespaces and deletion syscalls denied, the reference worker tests
passed 3/3: automatic color from a recovered clip, automatic color from a
confirmed publication while recording continued, and refusal of absent SPS
color with source custody retained. The fixture also exercised the existing
cancellation and access-denial paths.

The synthetic command fixture passed 2/2 explicit runs: automatic BT.709
and the existing explicit BT.601 option, each through a TLS controller,
video archive and still generation. A separate invalid-option test passed
1/1. An initial automatic run failed because its disposable leaf certificate
was not self-signed as required by the test's trust configuration. After
using a matching self-signed synthetic certificate, a second run exposed a
reporting mismatch: the command logged the policy rather than the resolved
color. The command now logs the actual still color, and the final runs passed.
Strict-remote job `j-30110656841646205` checked the scoped-TLS command on
`ts1`; its relevant source hashes matched the workspace.

These results do not establish physical camera handoff, direct live capture,
production TLS admission, uninterrupted recording or retention. No camera
setting was changed. The existing fallback recorder was active with six files
modified within five minutes after the checks.

### Bounded media reaccept ownership (2026-11-15)

A caller-driven `media_reconnect::Reaccept` owner now retains one bound
listener, at most one accepted pipeline, and a bounded queue of retired source
tails. Admission checks pristine inputs before constructing a wait, reserves
one strictly advancing connection key and finite attempt budget, and fences a
wait dropped even before its first poll until the caller acknowledges the
interruption. The caller must transfer retained tails explicitly before
exceeding the configured queue bound. The owner sends no camera control
request and does not authenticate device identity or establish continuity,
durable archival, effect settlement, or an automated recording service.

Strict-remote build `j-30110656841646206` compiled the listener integration
binary on `ts1`. The wrapper returned 102 because it correctly refused to
transfer a Linux executable to macOS. The worker and workspace hashes matched
for the reaccept module and integration test. The Linux binary then passed
2/2 tests in an isolated network namespace with filesystem deletion denied.
The new case exercised both unpolled and polled cancellation, a denied peer,
two synthetic FLV-header connections, source-tail transfer, and the attempt
and capacity fences. It did not exercise media frames or the physical camera.

A read-only check found the fallback service active, with six MP4 files
modified within five minutes. A scan of filename timestamps over the previous
24 hours found two adjacent starts separated by 94 seconds; adjacent file
durations were shorter than those separations. Those are possible coverage
gaps, but filename clock semantics and actual capture intervals were not
independently established. This observation does not prove their duration or
that other intervals have continuous coverage. No camera setting changed.

### HTTP stream reaccept with effect custody (2026-11-15)

A caller-supervised HTTP media reaccept bridge now moves the original committed
camera-setting effect and historical readback to a successor connection. It
requires the original pipeline to have stopped, checks the listener address and
owning task, retains the complete retired source, and requires a strictly newer
connection key through the existing bounded reaccept owner. A refusal retains
the input owners. The bridge sends no camera request; matching the listener
address, task, admission policy or historical readback does not authenticate a
new peer, establish fresh settings, settle the effect or prove uninterrupted
coverage. Archive workers and earlier returned records remain caller-owned.

Strict-remote job `j-30110656841646212` compiled both relevant integration
targets on `ts1`; its wrapper returned 102 after refusing to copy a Linux
executable to macOS. The worker and workspace source hashes matched for the
new bridge, the HTTP media owner, the bounded reaccept owner and both test
files. In isolated Linux network namespaces with deletion syscalls denied,
the two listener tests passed 2/2. Their synthetic encoded H.264 case created
segments on two connections and reconstructed each original source byte from
returned records and the retained tail.

The HTTP A/V transition test passed 1/1. It archived and read back the old
connection's retained source, transferred the same committed-effect digest,
rejected a live-source transition and a repeated connection key, and obtained
a first synthetic A/V segment on the successor connection. Two related network
budget exhaustion regressions passed 2/2. The new successor segment was not
published by that transition test, and no physical camera was contacted. This
bridge is not yet an unattended reconnecting recording service; the previous
physical camera effects, direct live capture, and 30-day continuous retention
remain unverified. The existing fallback recorder was active with six files
modified in the prior five minutes at the last check.

### Managed old-tail publication before reaccept (2026-11-15)

The HTTP A/V recording owners now have a bounded transition that combines a
stopped, drained archive driver with its existing listener, source-tail
publisher and reaccept bridge. It checks the actual old source and A/V worker
state before beginning. The transition retains the old archive and effect,
publishes each held source range, and refuses successor admission until the
source driver finishes. A failed or indeterminate publication fences the
transition and returns its owners for reconciliation. Publication completions
and receipts are returned to the caller, not silently treated as independent
proof of long-term retention.

A bounded automatic step can prepare a fresh framer and dimension-constrained
recorder from explicit source settings, allocate the next connection and
generation claims, and accept on the retained listener. Each wait consumes
the finite attempt budget; a dropped wait requires acknowledgment and its
source claim is not reused. Each automatic step checks the exact original
task, runtime and clock mapping. The caller still drives the step loop, handles
receipts and reconciliation, supplies successor archive resources, and runs
A/V bootstrap and publication. This is not yet an unattended recording service.

Strict-remote job `j-30110656841646217` compiled the two integration targets
on `ts1`; its wrapper returned 102 because it rejected copying Linux binaries
to macOS. The relevant bridge, source, listener and test hashes matched the
workspace. On the Linux worker, with isolated network namespaces and deletion
syscalls denied, six selected tests passed: the A/V transition success and
source-publication refusal (2/2), network and bootstrap exhaustion regressions
(2/2), and listener reconnect contracts (2/2). The synthetic A/V case read
back the old original source after publication, fenced a cancelled accept,
used a new source identity, and bootstrapped a successor A/V segment. The
refusal case reconstructed the still-owned original bytes and confirmed that
reaccept remained fenced. Wrong clock mappings were refused before and after
tail publication. The tests did not contact the physical camera, publish the
successor A/V segment, establish uninterrupted coverage or resolve prior
camera-setting effects. The existing fallback service was active with six MP4
files modified in the preceding five minutes after these tests.

### Successor A/V archive after reaccept (2026-11-15)

The bounded HTTP A/V reconnect transition can now attach an accepted successor
and a separately provisioned source/A/V archive to the normal coordinated
bootstrap driver. That driver validates the new source key, caller-supplied
camera claim, retention and worker readiness before reading media. The old
source-tail driver, old A/V worker, camera effect and listener remain retained.
A rejected attachment returns the connection, effect, storage and old owners,
as well as the last reserved source key, attempts used and original finite
attempt limit. This does not automatically provision storage, start a service,
authenticate the successor camera, or establish continuous capture.

Strict-remote job `j-30110656841646219` compiled the two integration targets
on `ts1`; its wrapper returned 102 after refusing Linux-to-macOS artifact
transfer. The changed reconnect modules and both tests matched workspace
hashes on the worker. With isolated network namespaces and deletion syscalls
denied, seven selected tests passed: transition recording and two refusal
cases (3/3), network and bootstrap exhaustion regressions (2/2), and listener
contracts (2/2).

The synthetic recording test published and read back two A/V segments from
each connection, decoded a 160 x 128 video picture from each segment, verified
audio frames and an audio track, and published and read back each connection's
remaining original-source tail. It did not independently decode audio. A
mismatched successor-storage test retained the original effect, old archive,
listener, attempted source identity and attempt budget. No physical camera was
contacted; actual G4 handoff, direct live recording, uninterrupted operation,
automatic storage provisioning and 30-day retention remain unproved. The
existing fallback service was active with six MP4 files modified within five
minutes after the tests.

### Reuse settled archives across a reconnect (2026-11-15)

The bounded reconnect owner can reuse its existing source and A/V archive
owners for a successor without creating a new storage directory. It requires
an empty, drained source-tail plan, matching retention and camera claims, and
locally settled source and A/V journal/keeper state. It also checks the old
muxer's source key. A pending publication, fenced state, mismatched retention,
or existing A/V rollover custody refuses the transfer with its owners
retained; rollover custody is not automatically verified or reused. The old
muxer and terminal source observations remain separately owned. The check is
local state, not proof of independent durable custody or physical identity.
Every later publication retains its normal authority and journal checks.

The initial integration fixture overflowed its normal Linux test-thread stack;
a diagnostic 16 MiB test stack passed but was not accepted as the final result.
The handoff was split into heap-owned preparation, A/V retirement and attachment
phases, and the test's bootstrap and recording phases were separated. A staged
boxed bootstrap-to-archive handoff also retains the original refusal owners.
The final selected tests ran with the normal thread stack.

Strict-remote job `j-30110656841646235` compiled the two integration targets
on `ts1`; its wrapper returned 102 after refusing Linux-to-macOS artifact
transfer. Relevant workspace and worker source hashes matched. In isolated
Linux network namespaces with deletion syscalls denied, nine selected tests
passed: archive reuse, wrong retention, separate successor storage, tail
refusal and wrong-storage refusal (5/5); two network-exhaustion regressions
(2/2); and listener reconnect tests (2/2). The reuse fixture did not create a
successor storage root; it published and read back source tails and A/V clips
from both synthetic connections in the same archives, decoded video frames,
and checked audio-frame and track presence. It did not independently decode
audio or contact the physical camera. The existing fallback recorder remained
active with six MP4 files modified in the preceding five minutes. The caller
still drives the transition and bootstrap; real G4 takeover, uninterrupted
recording, automatic rollover custody and 30-day retention remain unverified.

### Retain managed recording policy across reconnect (2026-11-15)

A stopped, drained HTTP A/V managed recorder can now park its recording
owners for the existing reconnect transition while retaining its generation
plan, creator and rollover custody, and remaining audio allowance. It refuses
to park a live source or one whose recording workers have not drained. A
successor must have an advancing source claim, matching caller-supplied camera
claim and task, and the same caller-supplied clock mapping. These claims do not
independently authenticate a physical camera, prove the listener binding or
settle a committed camera effect. An active creator is retained without being
polled or canceled. The caller still decides whether the stop warrants a
reconnect and must supervise every phase and reconcile its effect and custody.

Strict-remote job `j-30110656841646247` compiled the two test targets on `ts1`;
the wrapper returned 102 because Linux binaries were refused for transfer to
macOS. The three changed source/test hashes matched the worker. On Linux with
network namespaces isolated, deletion syscalls denied, and the normal test
stack, the four HTTP reconnect cases and two listener cases passed (6/6). The
archive-reuse fixture checks rejection of a wrong clock and a live-source park,
then preserves the finite plan and audio budget, schedules its next generation,
and reads back both synthetic A/V generations and original source tails. It
creates the managed owner after the first source has ended; preserving an
already running creator or previously installed rollover custody across a
reconnect remains untested. This is not a continuously running service.

The separately selected `checkpointed_http_av_eof_does_not_plan_another_generation`
fixture overflowed its normal Linux test-thread stack before reaching the
rollover helper. It passed only as a diagnostic with `RUST_MIN_STACK=16777216`;
that is not a normal-stack pass, and whether the overflow predates this change
has not been established. A preliminary fixture split did not resolve it and
was removed. The full integration suite has not been qualified. No physical
camera was contacted and no camera setting was changed by these tests.

### Caller-driven managed EOF supervisor (2026-11-15)

The HTTP-started managed A/V path now has a bounded supervisor that owns the
recording, listener and clock binding. Only a returned EOF starts automatic
source-tail retirement and reaccept; other media stops do not trigger another
connection. The supervisor retains each stopped phase and its parked managed
owner, returns exact recording, tail and bootstrap events to its caller, and
keeps the previous source boundary until explicitly transferred. A later EOF
cannot proceed while that boundary is still held. Listener refusals require
explicit retry, interrupted waits require acknowledgment, and the original
finite attempt limit is enforced. The owner has no standalone service loop,
crash-restart persistence, independent peer identity proof, or automatic
resolution of a committed camera effect. Existing A/V rollover custody still
requires reconciliation before archive reuse.

Strict-remote job `j-30110656841646258` compiled both integration targets on
`ts1`; the wrapper returned 102 after refusing to copy Linux executables to
macOS. Five relevant workspace/worker source and test hashes matched. On Linux
with the normal test stack, isolated network namespaces, and filesystem
deletion denied, the two supervisor tests passed (2/2), four reconnect tests
passed (4/4), and two listener tests passed (2/2). The synthetic success case
observed EOF on the first source, automatically archived its source tail,
accepted a second source, reused the archives and resumed the same manager.
It checked the previous-boundary fence, read back four A/V clips, decoded a
160 x 128 video frame from each, checked audio-frame and track presence, and
read back the second source's remaining tail. The failure case required an
explicit retry after each of two listener timeouts, then confirmed the attempt
limit fenced further retries while retaining the transition and parked owner.
No physical camera was contacted. Independent audio decoding, unattended service
operation, live G4 handoff, uninterrupted capture and 30-day retention remain
unverified. The separate `checkpointed_http_av_eof_does_not_plan_another_generation`
fixture continued to overflow its normal test-thread stack in the prior run;
the full integration suite is not qualified.

### Reconnect after an A/V archive rollover (2026-11-15)

The EOF supervisor can now carry an existing A/V rollover chain through a
reconnect. After the old source tail is archived and a successor is accepted,
it retains the old muxer and source owners while a task-admitted blocking worker
checks the complete rollover custody against the current journal and keeper.
Only a successfully drained verification permits the existing archive and
custody to enter the successor bootstrap. A refused worker admission requires
explicit retry; a failed, canceled, or uncertain check leaves the exact owners
available for reconciliation. The result is still caller-driven and does not
prove independent custody, physical camera identity, crash recovery, or
continuous coverage. The original synchronous reuse entry point continues to
refuse rollover custody unless the verification path is used.

The managed owner's variants now hold their large recording and rollover owners
on the heap, and the preflight and switch handoffs use heap-owned stages. The
previously overflowing
`checkpointed_http_av_eof_does_not_plan_another_generation` fixture was also
split into smaller async phases and passed on the normal Linux test stack.
The standalone experimental recorder's source was adjusted for the boxed owner;
its prepared-workspace `cargo check` completed on `ts1` as strict-remote job
`j-30110656841646277`. The prepared workspace's edited trial source hash matched
the original workspace source. An earlier direct-manifest check was refused
because that source tree intentionally lacks its generated rustls vendor path.

Strict-remote job `j-30110656841646287` compiled the final integration targets
on `ts1`; the wrapper returned 102 after refusing to transfer Linux binaries to
macOS. Relevant workspace and worker source hashes matched. On the normal test
stack with isolated network namespaces and filesystem deletion denied, the
four managed-supervisor tests passed (4/4), four reconnect tests passed (4/4),
and two listener tests passed (2/2). The forced-rollover cases filled a small
synthetic archive, performed one journal rollover, disconnected, verified its
retained switch chain, and resumed the successor. They read back six A/V clips,
decoded a 160 x 128 video frame from each, verified audio-frame and track
presence, read back the successor source tail, and rechecked the retained
rollover history. One case first refused verification admission and confirmed
that an explicit retry was required. Independent audio decoding was not tested.

In the checkpointed A/V group, ten tests passed on the normal stack, including
automatic rollover, cancellation, source-tail cases, and the formerly failing
EOF fixture. The process then aborted on stack overflow in the older manually
driven `checkpointed_http_av_rollover_denial_retains_pending_media` fixture;
a separate normal-stack run of
`checkpointed_http_av_start_archives_supplied_audio` also overflowed. Both
passed only in separate larger-stack diagnostics, which are not normal-stack
passes. The remaining private-camera replay test was not run. Therefore the
full integration suite remains unqualified. No physical camera was contacted
or reconfigured, and direct live recording, unattended service operation,
crash recovery, uninterrupted capture and 30-day retention remain unverified.

### Scoped listener separation and normal-stack A/V fixtures (2026-11-15)

The reconnect media owner can now split its task-scoped listener from a
listener-independent owner containing the exact active pipeline, retained
source tails, source claim, interrupted-wait flag and finite attempt state.
The HTTP bridge carries that owner together with the original committed effect
and historical readback. This transfer does not drain work, resolve an
interrupted wait, settle the effect, prove device identity, authorize a retry,
or make recovery durable across process failure. In the synthetic
attempt-limit case, the returned effect digest and attempt bounds were checked
and the detached owner satisfied a compile-time `static` bound. The active
pipeline and interrupted-wait variants were not independently exercised by
this new split test. Other supervisor phases and the experimental recorder's
scoped shutdown path still need explicit recovery and integration.

The two older manually driven A/V rollover fixtures previously overflowed the
normal Linux test stack. Their preflight and rollover work now runs in a
separate heap-owned async phase, retaining the original checks, including the
denied-replay custody check. Strict-remote build job `j-30110656841646289`
compiled both integration targets on `ts1`; its wrapper returned 102 when it
correctly refused to copy Linux binaries to macOS. The four changed source and
test files matched the worker's SHA-256 hashes. With the normal test stack, an
isolated network namespace and deletion syscalls denied, the final HTTP target
passed 38 tests, with two private-camera replay tests ignored; the listener
target passed 2 tests. These are synthetic results, not live camera, complete
service, crash-recovery, continuous-coverage or 30-day-retention proof. No
physical camera was contacted or reconfigured in this work.

### Reconnecting supervisor recovery handoff (2026-11-15)

The caller can now split a supervisor in the `Reconnecting` phase into its
scoped listener and clock bindings and a listener-independent recovery owner.
The recovery owner retains the bridge's unresolved camera effect and media,
the predecessor A/V worker, source-tail driver and completion flags, parked
manager plan and workers, source/camera claims, custody limit, pending old
boundary, reconnect policy and supervisor decision flags. The original
parked and supervisor clock bindings are returned separately. A request in
another phase, or with a separately held listener, returns the supervisor
unchanged. This is a one-way custody transfer: it does not join workers, resume
the service, settle an effect or make any of these owners crash-durable.

Strict-remote job `j-30110656841646290` compiled the HTTP and listener test
targets on `ts1`. The wrapper returned 102 after rejecting the Linux binaries
for the macOS host. SHA-256 hashes of the changed supervisor, manager and HTTP
test matched on both hosts. On the normal Linux test stack in an isolated
network namespace with deletion syscalls denied, all four supervisor tests and
both listener tests passed. The attempt-limit scenario checks the original
effect digest, both clock mappings, retry flags, preserved parked owner, and
that the detached recovery owner has no scoped lifetime. It also first checks
that detaching while recording is refused without consuming the supervisor.
Recovery with a live candidate, an interrupted accept, running workers, and
other supervisor phases is not independently qualified. The experimental
recorder does not yet use this handoff; no physical camera was contacted or
reconfigured, and production service, live direct A/V, crash recovery and
30-day retention remain unverified.

### Reconnect recovery cancellation and camera stream selection (2026-11-15)

Detached reconnect recovery now requests cancellation of the source-tail
worker, predecessor A/V worker and parked creator. Its join operations retain
the exact tail and A/V completions on the recovery owner, while a parked creator
completion remains in its management parts. Repeated joins preserve an already
retained completion. A false join result is not proof of a drained worker, and
this API does not itself settle the camera effect, preserve custody across a
process crash or handle every other supervisor phase.

Strict-remote jobs `j-30110656841646291` and `j-30110656841646292` compiled
the HTTP target on `ts1`; each wrapper returned 102 after rejecting the Linux
executable for the macOS host. Final supervisor, manager and test hashes
matched the worker. In an isolated network namespace with deletion syscalls
denied and the normal test stack, all five supervisor tests passed. The new
case detaches while a source-tail publication has been admitted, requests
cancellation, and confirms that joining returns and retains its actual
completion. It also checks that a second join preserves that completion. Active
predecessor A/V and creator cancellation remain untested by this case.

The fallback service on `trj` requests Scrypted's `medium` stream. A recent
completed fallback file probed as H.264, 1280 x 720, video only. Scrypted
advertised a `high` stream at 2688 x 1512 and a `medium` stream at 1280 x 720;
that advertisement is not a new live high-resolution capture. Its source shows
that starting a new stream can issue camera requests and potentially reset
streams if the audio profile changes. The fallback was left running and recent
files were observed; this does not establish gap-free coverage. The unresolved
physical camera effects and safe high-stream handoff remain to be reconciled.

### General supervisor recovery ownership (2026-11-15)

The supervisor now has a general, typed recovery conversion for recording,
reconnection, archive verification, startup, and the explicitly represented
refusal phases. It returns the scoped supervisor and phase listeners and clock
bindings separately from a listener-independent recovery owner. The latter
retains the exact phase, nested refusal class, source and effect custody,
parked manager, previous boundary, policy and decision flags. A compile-time
check confirms the recovery owner does not borrow the runtime scope. This is a
one-way in-memory transfer, not worker drainage, crash recovery, effect
settlement or permission to resume a physical camera. Events already returned
from the supervisor remain the caller's responsibility.

Strict-remote jobs `j-30110656841646293` through `j-30110656841646297`
compiled the HTTP test target on `ts1`. The wrappers returned 102 because they
refused to copy a Linux executable to macOS. The final module declaration,
recovery source and test hashes matched on both hosts. With the normal Linux
test stack, an isolated network namespace and deletion syscalls denied, all
seven supervisor tests passed. Three types of phase were exercised: a recording
after successor capture, a reconnect with a source-tail worker admitted, and
a rollover verification with an accepted candidate and admitted worker. The
last two cases aborted and joined the actual synthetic worker and retained the
effect; the recording case read back the successor source and A/V clips after
the transfer. The conversion's individual stopped/refusal variants and startup
phase were not independently exercised. The recorder command does not yet use
this conversion or drain every possible returned owner, and no live-camera,
unattended-service, restart, continuity or 30-day-retention claim follows.

### Bounded cancellation and receipt retention (2026-11-15)

The general recovery owner now offers a bounded drain for the normal recording,
reconnecting, verification and startup phases. It requests cancellation and
joins source, A/V, verification, creator and rollover workers separately.
Source, A/V and verification completions are retained in the drain owner
before any later join; creators and rollover owners retain their own results.
The `join_available` report labels missing completions explicitly and does not
assert that a missing completion means quiescence. Refusal phases and a parked
manager with an unexpected active owner are returned unchanged without starting
this drain. The drain remains volatile and is not used by the recorder command.

Strict-remote jobs `j-30110656841646298` through `j-30110656841646300`
compiled the HTTP integration target on `ts1`. The wrappers returned 102 after
refusing to copy Linux executables to macOS. Final manager, recovery and test
hashes matched between hosts. In an isolated network namespace, with deletion
syscalls denied and the normal Linux test stack, all eight supervisor tests
passed. They include running synthetic A/V, source-tail and verification
workers; exact completions and the camera-effect permit were retained. A
dropped later wait did not discard a previously retained A/V completion. An
unsupported stopped phase was refused with its archive owner intact. Startup,
all refusal variants, concurrent worker combinations and interruption while
`join_available` itself is awaiting a later worker remain untested. This does
not establish live G4 capture, a standalone recorder, effect settlement,
crash recovery, continuous coverage or 30-day retention.

The existing standalone trial source also passed a strict-remote `cargo check`
on `ts1` as job `j-30110656841646301` from its prepared workspace. Its trial
source matched the project copy and its path dependencies used the current FSS
crates. This is a compatibility check only: the trial was not changed to use
the new drain or supervisor.

### Refusal-state drainage and active-worker checks (2026-11-15)

The detached recovery drain now traverses the source, A/V and verification
owners inside every represented supervisor phase, including nested reconnect,
reuse and startup refusals. A missing phase or an inconsistent parked manager
with an active owner is still returned unchanged. Source coordinator and
detached archive-parts owners can request cancellation and join their exact
workers; detached A/V parts use the same completion-to-scheduling-state logic
as the live archive driver. A worker-status view checks outstanding source,
A/V, verifier, creator and rollover handles. `finish_if_drained` retains the
drain owner if any such handle still needs joining. It does not attest to closed
sockets, successful effects, independent durability or recording continuity.

Strict-remote job `j-30110656841646304` compiled the final HTTP integration
target on `ts1`; the wrapper returned 102 after refusing to copy its Linux
executable to macOS. The nine changed source and test files matched their
worker SHA-256 values. With the normal test stack, isolated network namespace
and deletion syscalls denied, the complete HTTP integration target passed 43
tests with two owner-supplied private-camera replays ignored. The nine focused
supervisor cases include live synthetic source, A/V and verifier workers; each
refused `finish_if_drained` before the active handle was joined. A genuine
wrong-retention reuse refusal retained its accepted candidate and camera effect
through drainage. Stopped-archive and startup-seal cases were constructed from
a drained synthetic recorder; they were not independent real-world failures.
The remaining individual refusal variants, adverse combinations of workers,
and a dropped wait during `join_available` still need targeted qualification.
The experimental recorder has not yet been wired to this drain, and no camera
was contacted or reconfigured. Full direct capture, unattended service, crash
recovery and the 30-day retention requirement remain unverified.

### Experimental command drives supervised reconnect (2026-11-15)

The checkpointed HTTP A/V trial command now offers an explicit
`--lab-http-av-supervised` mode, requiring `--lab-http-av-auto=1..7`. It drives
the managed recorder through EOF, tail publication, successor acceptance,
archive reuse, optional rollover-custody verification and successor startup.
It retains the bounded decision events and old-source boundaries, then requests
cancellation and joins the phase workers before returning. A finite accept
timeout may be retried within the existing two-attempt bound; a denied peer or
other admission failure stops for reconciliation. The command remains bounded
to 1..8 published segments, at most 4096 decisions and 16 retained boundaries.
The original non-supervised trial behavior remains separately available.

Strict-remote jobs `j-30110656841646305` through `j-30110656841646309`
built the command on `ts1`; their wrappers returned 102 because they refused
to copy the Linux executable onto macOS. The final executable SHA-256 was
`b58ddfbaa8c411ad84a5766d9c462ab2c97773434dc23acdc81e5b353b15cc48`.
The CLI, A/V command, supervised driver and both fixture scripts matched their
project and worker source hashes. In an isolated network namespace with
deletion syscalls denied, the full command fixture passed 26 synthetic A/V
scenarios and seven argument refusals. The trace at
`/data/tmp/fss-supervised-fixture-20261115-06/trace-02` recorded 86 denied
deletion attempts.

The new scenarios include a two-connection recording with three read-back A/V
segments, a four-segment recording through two archive rollovers and one
verified archive reuse, and explicit stopped-and-drained cases for a missing
successor and a denied peer. The latter records one denial and no automatic
retry. A one-generation rollover attempt was initially expected to complete,
but stopped after three published segments because the successor needed a
second generation. It is retained as a separate expected exhaustion test;
the effect remains unresolved. Synthetic A/V samples and camera-local claims
do not establish physical camera identity, real capture, continuous coverage,
audio fidelity or 30-day retention. The trial's final segment limit can leave
unclosed source material in volatile custody; it is not an unattended service
or crash-durable recovery. No physical camera was contacted or reconfigured.

### Supervised stop: final received-source readback (2026-11-15)

After reaching its segment limit, the experimental supervised command now
plans the stopped pipeline's remaining received source ranges, publishes them
through its scoped source worker, drains that worker, and reopens the resulting
source roots. It checks the ordered offsets, lengths, dispositions, framing
claims, connection and camera claims, and SHA-256 digests against the held
originals. Refusals carry the corresponding owners in process for
reconciliation; that custody is not preserved across process exit. This
extends the preceding trial: the final received tail is no longer intentionally
left only in volatile custody on a successful supervised stop. It does not
cover bytes not read from the socket, finalize an incomplete GOP, settle camera
effects, or establish independent durability or crash recovery. The prior
non-supervised command retains its existing behavior.

Strict-remote build `j-30110656841646310` succeeded on `ts1`; its wrapper
returned 102 because the Linux executable could not be copied to macOS. The
worker executable SHA-256 was
`2ee728720d2c8d6d1e09a59e894aacc087b525e81eb361edd375f4db49d53626`, and
the changed source matched the prepared local and remote copies. In an isolated
network namespace with deletion syscalls denied, 26 synthetic A/V scenarios and
seven argument refusals passed. Focused repeats verified two tail records for
each of the normal supervised reconnect and rollover cases; traces and retained
fixtures are under `/data/tmp/fss-final-tail-20261115-01` and
`/data/tmp/fss-final-tail-20261115-02` on `ts1`. A deliberate final-tail
readback corruption or publication failure has not been independently tested
in this command. No physical camera was contacted or reconfigured.

### Retaining a refused A/V source tail (2026-11-15)

The A/V startup and recording owners now classify the specific
`TrailerPolicyMismatch` framing refusal as eligible for a checked source-tail
retirement. Framer refusal does not consume the rejected bytes; the retirement
planner still validates its owned ranges. Other framing errors and unaccepted
recording inputs are not thereby made eligible. On an eligible supervised
recording failure, the laboratory command drains its scoped workers and attempts
to publish that tail before returning its reconciliation error. It does not
retry a camera write. This concerns received local bytes, not unread socket
bytes, physical peer identity, effect settlement or crash-durable failure
custody. The earlier physical trial was video-only; this A/V change is not a
replay or a fix demonstrated against that trial's now-unavailable suffix.

Strict-remote build `j-30110656841646312` succeeded on `ts1`; the wrapper
returned 102 after rejecting transfer of the Linux executable to macOS. The
worker binary SHA-256 was
`efdad61223297fd1ae8b1309b8e5c769e5934124ad8b9a4328f6825e09b07cb1`.
In an isolated network namespace, the A/V fixture passed 29 synthetic cases
and seven argument refusals, including an exhausted network budget and a
malformed trailer after recording began or during startup. In the two framing
cases an independent fixture inspected the spool envelope and matched the
rejected synthetic trailer and subsequent tag header against a SHA-256-checked
object payload. This confirms those bytes were present in a content-addressed
spool object; the fixture does not independently traverse the publication graph.
The run and its deletion-denying trace are retained under
`/data/tmp/fss-supervised-framing-tail-20261115-05` on `ts1`; the trace
recorded 96 denied deletion attempts.

An earlier focused run and an earlier full run failed an incorrect fixture
assertion that hashed the entire spool envelope rather than its payload; the
revised checks parse the envelope and hash the payload. A separate first
bootstrap run failed its fixture's setup-fence classification; the corrected
fixture checks the one unresolved operation. These failed runs remain evidence,
not passing results. The new paths were not tested with a real camera, a
failed tail publication, or independent effect reconciliation. The existing
recorder was active with six recently modified files after testing.

Strict-remote test-build job `j-30110656841646313` also compiled the HTTP
integration target on `ts1`; its wrapper returned 102 when it refused to copy
the Linux executable to macOS. The new focused classifier test passed 1/1 on
that worker, with 45 other tests filtered out: both A/V owners accept the
specific trailer mismatch for attempted retirement and reject a buffer-limit
framing refusal. Its deletion-denying trace is retained under
`/data/tmp/fss-trailer-classifier-20261115-01`.

### Video-only trailer-refusal source readback (2026-11-15)

The video-only laboratory command now also handles the specific
`TrailerPolicyMismatch` after draining its workers. It retires the pipeline,
checks the camera claim against its source owner, publishes the held source
ranges, and reopens their roots to compare source offsets, framing claims,
dispositions and SHA-256 payload digests. The path works with or without the
separately requested restoration attempt; it does not authorize a retry or
claim the camera effect was settled. An unsuccessful publication or readback
returns the retained owners in the in-process error. The helper is shared with
the bounded A/V trial and does not establish unread socket coverage, continuous
capture, independent graph replication or crash recovery.

Strict-remote job `j-30110656841646314` built the trial command on `ts1`; its
wrapper returned 102 after declining to copy the Linux executable to macOS.
The worker executable SHA-256 was
`c60799cf7c89b8780fe783a665cf7afb42649c19fce4f9ea9ac2e944ca76ab10`;
both changed command modules matched their project and worker hashes. A
focused synthetic test passed for malformed trailers both with and without
restoration. A separate metadata-name-probe mismatch case also passed. These
tests verify the rejected synthetic trailer and next tag header in an
independently hash-checked spool payload, in addition to the command's own
source-root readback. The recorded physical trial's discarded suffix cannot be
recovered by this change, and no new camera operation was performed.

Against the same worker executable, the isolated video fixture passed 13/13
scenarios plus three checkpoint comparisons, three checkpoint/journal checks
and three simulated live observations. The separate restore fixture passed
20/20 scenarios and one argument refusal; the A/V fixture passed 29/29
scenarios and seven argument refusals. These are synthetic-camera results,
not physical-device qualification. The fixtures and deletion-denying traces
are retained on `ts1` under `/data/tmp/fss-video-failure-tail-20261115-02`
through `-04`; the traces recorded 30, 43 and 96 denied deletion attempts,
respectively. Tail-publication failure and process-crash recovery remain
untested in the new video failure path.

### Batched reconnect tail with a passive camera sample (2026-11-15)

A fresh 20-second passive capture of the already-running G4 medium push
provided camera-derived media without a camera request or setting change.
The HTTP controller and both connection endpoints in the replay were
simulated. The single 186,375-byte selected sample was replayed twice, once
per simulated connection, through both the old and changed Rust commands.
The FLV header and starting boundary were synthesized; the AVC configuration
came from a closed fallback recording that matched on two observations, and
the AAC configuration was a historical unverified hypothesis. The peer's
physical identity, configuration epoch, capture time and A/V synchronization
were not independently established.

With that exact input, the unbatched command stopped after one archived A/V
segment during reconnect source publication; its source deployment contained
128 roots, the configured maximum. Its payload-free classification was
`archive`, which alone does not identify the underlying storage error. The
changed supervisor enables the existing bounded batch operation before
publishing a predecessor tail, and the changed command completed the simulated
reconnect with two archived/read-back A/V segments: 300 video samples and
156 audio frames, with Rust decoding 1280 x 720 video. Its source deployment
contained four roots. These paired results support the batching explanation;
they do not prove every possible cause of the original refusal. The command
did not independently decode audio in this test.

The old binary SHA-256 was
`a8c5c38c1f1dc67ae083acdf9df6dca02dcd59961c94f80e3868b6d2b80005e9`;
the paired changed binary was
`38bcbdf1d8ffe06cc769ba7744f7706faed2e9b8e08a0034f4565e2ac8ae2327`.
The changed binary was built by strict-remote job `j-30110656841646317`,
whose wrapper returned 102 after rejecting Linux-to-macOS artifact transfer.
Both private archives remain in mode-0700 tmpfs directories
`/dev/shm/fss-unifi-paired-supervision-20261115-01` and `-02` on `ts1`;
their traces are under corresponding `/data/tmp` paths and the diagnostic
archives are outside the fallback retention policy. Earlier separate passive
samples failed before post-recording readback with 128 source roots; their
exact payloads were not retained for a paired replay.

Batching is bounded to 256 source records and 1 MiB per batch, falling back to
a single record when necessary. It does not implement source-store rollover or
unlimited recording: enough batches can still exhaust the 128-root store.
This experiment does not establish direct camera ownership, a physical
reconnect, unattended operation, crash recovery or 30-day retention.

The subsequent CLI snapshot added payload-free batch accounting and passed
30/30 synthetic A/V scenarios plus seven argument refusals. Its new stress
case required more than 128 predecessor-tail records to be offered in bounded
batches; the resulting source deployment had four roots. A first version of
that synthetic stream failed during A/V publication before reconnect and had
added audio timestamps that duplicated existing fixture timestamps; the exact
publication refusal was not recorded. After the fixture was corrected to use
distinct subsequent timestamps, the stress case passed; the earlier failed
run remains separate evidence. Strict-remote build
`j-30110656841646318` succeeded on `ts1`; its wrapper returned 102 only after
refusing to transfer the Linux executable to macOS. Its binary SHA-256 was
`d4ef58e5733511d57695e53cec0d5e167328613b62f8cb53beff9b744d4e67ab`.
The full synthetic fixture and deletion-denying trace are retained under
`/data/tmp/fss-supervised-batching-regression-20261115-03` on `ts1`; the
trace recorded 101 denied deletion attempts.

Strict-remote job `j-30110656841646319` also built the HTTP integration
executable; its wrapper returned 102 after refusing the Linux artifact transfer.
The worker executable SHA-256 was
`718899d1d7dd6ec2cfaf4410f451ae93b9e9e3203cf20519b734f62b26fe46c6`.
In an isolated network namespace, the complete target passed 44 tests with
two owner-supplied private-input tests ignored. The deletion-denying trace at
`/data/tmp/fss-supervisor-batch-contract-20261115-01/trace` recorded 138
denied attempts. The supervisor fixture was updated to accept explicit batch
offers; the prior lower-level batch custody and failure tests remain part of
the run.

### Source-root capacity before journal intent (2026-11-15)

The source worker now checks its exclusively owned publisher before preparing
a new journal intent. When the local source store has reached its visible-root
limit, the candidate slot is absent, the journal and keeper are locally
settled, and current retention authority permits the candidate, it returns a
distinct `RootCapacity` refusal with the candidate pin and local root counts.
The original source or batch remains with the drained worker. Existing or
staged slots and unsettled journals follow their original reconciliation paths;
the observation is not a reservation, a custody proof, or permission to
replace or delete a store. A constant-time publisher count avoids scanning the
root set on each new candidate. The experimental supervisor reports the
capacity classification but does not automatically retry it.

A focused synthetic worker test fills a one-root store, successfully replays
its already-confirmed root, then verifies that a different record stops before
either journal anchor changes. It also offers two ordered source records as a
batch, checks both original digests and dispositions after the capacity
refusal, and verifies that a pre-existing unresolved intent still reports a
candidate conflict. The final focused test passed 1/1 on `ts1` under a
deletion-denying trace. Strict-remote build `j-30110656841646323` compiled the
test executable, SHA-256
`d72d9f5260df96d0c5c5719ee7a08b87423654152b1213be2a3034025de04a93`;
the wrapper returned 102 after refusing to transfer a Linux binary to macOS.
The trace at `/data/tmp/fss-source-root-preflight-20261115-04/trace` recorded
two denied deletion attempts.

An earlier test snapshot with the same production source passed all 13
non-ignored storage cases in separate processes, with one helper-child test
ignored when invoked directly. The earlier combined run had 12 passes, one
failure and one ignored: two tests reused the same process-derived temporary
directory, and the deletion guard preserved the first directory. Each case
then passed with a separate private temporary directory; the failed combined
run is not relabeled a pass. Those split traces under
`/data/tmp/fss-source-root-preflight-20261115-03` recorded 283 denied deletion
attempts. On the same production source, the experimental A/V command passed
30/30 synthetic scenarios and seven argument refusals; its trace under
`/data/tmp/fss-source-root-preflight-cli-20261115-01` recorded 101 denied
deletion attempts. Strict-remote command build `j-30110656841646322` produced
worker executable SHA-256
`d6d1c899598ab9f217aa0e6643c36e38925632d8c3f6c2c1cf12e203e475ad94`;
its wrapper likewise returned 102 after rejecting Linux artifact transfer.

This is a safe stopping point, not automatic source-store rollover. The
existing source-journal rollover keeps the same deployment and requires its
confirmed root to already be ledgered there. Moving to a fresh deployment
requires a separately witnessed cross-store transition, retention of the old
history, and crash/recovery qualification. No physical camera was contacted.

### Copying a confirmed source to a fresh store (2026-11-15)

The source worker now has a bounded cross-store copy operation for the last
confirmed single source or source batch. It checks the predecessor's settled
journal and keeper, reads its ledgered graph, checks the supplied camera claim,
and publishes the same root through an empty-ledger successor's own journal
and keeper. It then verifies the receipt and reads the successor graph back.
Both stores and any pending predecessor source remain with the caller. A
publication failure retains the destination for reconciliation; a failed
post-publication readback returns the actual ledger receipt. This is a copy,
not an activated successor, independently witnessed cross-store binding, or
proof that the two paths refer to physically independent storage.

Strict-remote job `j-30110656841646327` built the storage contract executable
on `ts1`. Its wrapper returned 102 when it refused to transfer an unrelated
Linux executable to the macOS host; the worker build itself reported success.
The test binary SHA-256 was
`22fb1e0382b39c9e2fb82e8062d3c32d07eb8b24b2ae366ee38d1d9d202c68cd`.
Worker and local source hashes matched: source worker
`d54a8283b6b3a0aa48aacd322db52102be89f6c07d4fb725f351edd91b656221`,
and storage contract
`9e0e5233b0c84a1f6ca91f22539258b958474508e0b84aa02ffdc67e851786f4`.

The focused capacity test passed for a confirmed single source and a pending
batch: it checked wrong-camera refusal, successful copy, refusal to reuse a
nonempty successor, withdrawal of retention after preparation, and withdrawal
of read authority after publication while retaining the receipt and owners.
The batch test passed after copying a two-record confirmed batch and comparing
both source byte ranges. It also released and reopened the successor using
journal and keeper minima held in the test process, then read the batch and
compared the ranges again. This reopening is not a process-crash test or proof
that the minima and the relationship between stores were durably retained.

The complete storage contract target was then run case by case in separate
private temporary directories on `ts1`: 13 passed and its helper-child case
was ignored when directly invoked. Deletion syscalls were denied in every
case; traces remain under `/data/tmp/fss-source-fresh-suite-20261115-01`.
Separate directories avoid the previously observed collision between tests
that reuse a process-derived temporary path when deletion is denied. No
physical camera was contacted. The existing recorder was active and six
fallback files had been modified within five minutes at the check.

This does not yet transfer pending input, activate or automatically provision
a successor, preserve a durable cross-store recovery inventory, reconcile the
physical camera effects, or establish direct live capture, uninterrupted
recording, crash recovery, or 30-day retention.

### Distinguishing startup name-probe refusals (2026-11-15)

The experimental HTTP video and A/V commands previously collapsed every
unsuccessful stream-name probe into the same final error. They now also emit a
payload-free reason, distinguishing a conflicting name, prefix limit, empty
or incomplete source, timeout, clock or owner-state refusal, and categorized
source or metadata-inspection errors. The explicit trailer-policy mismatch has
its own classification. The result is diagnostic: it does not authenticate the
peer, prove a framing boundary, authorize another camera write, settle either
effect, or alter the existing restoration and owner-draining behavior.

The original lab manifest lacked its generated `vendor/rustls` directory, so
the first strict-remote invocation was refused before compilation with
`RCH-E415`. An isolated workspace was constructed from the source copy manifest
and the patched vendor directory of an earlier local lab workspace. A locked
build in that workspace, job `j-30110656841646329`, then refused to update its
stale lockfile. A separate new workspace resolved dependencies offline; its
retained worker lockfile SHA-256 is
`885cd06f02ef045f569cadeb9ad2a6da2e1ed1b5c59431ed629902c3a15a50a3`.
Job `j-30110656841646330` built the command on `ts1`; the wrapper returned 102
after rejecting transfer of a Linux executable to macOS. The worker executable
SHA-256 was
`5d00200543210af66e804661cc1832fb18b6d4768f3abb0ed77d24df92848376`.
The restore helper and video/A/V command sources matched their local hashes:
`88ea28d053e18cb3a68172a944e7c5ab43856388d5e2b8626555b850a42f4464`,
`89163df4d2c44c265ca931abd263b553d8be3c8b2f290b8c2825e57c5ce77d8f`, and
`25e804eb44dd423b8e0390dcb30484d3d882f1704d49762c67786bfa7e1a0245`.

Job `j-30110656841646331` built the test executable on the same worker; its
wrapper had the same foreign-artifact refusal. Three focused helper tests
passed, including distinct metadata, trailer, work-limit and cancellation
classifications. In a private network namespace, six synthetic-camera cases
passed: a matching name, a wrong name, and malformed metadata, separately for
video and A/V. The four refusals checked their specific reason and retained
the existing unsettled-effect and restoration expectations. The fixture source
SHA-256 was
`d876f5fe2e92168af17fff7ceed0cf9412d6d96c19803b71dc1d24995690dd48`.
The first fixture attempt failed before discovery because the isolated network
was missing its required neighbor entry; the corrected run is separate from
that failure. Deletion syscalls were denied; the successful fixture trace at
`/data/tmp/fss-name-probe-reasons-20261115-02/trace` recorded nine denied
attempts, and the focused unit trace recorded none. The fixture contacted no
physical camera. The existing recorder remained active with six recent files.

The new code does not prove a physical G4 high-stream capture or restoration.
It also does not finish automatic onboarding, direct recording, crash recovery,
continuous coverage, or 30-day retention; the prior physical effects remain
unresolved.

### Cross-page discovery claims and cancellation (2026-11-15)

The fleet can now be constructed from up to 17 caller-labeled, completed
sweep pages, covering the page count needed by the existing bounded `/20`
planner. The merger refuses missing, repeated, invalid, or differently scoped
pages and caps distinct claims at 512. It processes pages by page number,
deduplicates equal claims and retains conflicts across pages. A fleet created
this way requires subsequent refreshes to provide a complete sweep under the
same caller-bound scope; a single-report refresh is refused. The caller still
owns the page observations and must establish their scope, freshness and
authority. Labels and matching claims do not authenticate devices or prove
that every host responded. This does not install or schedule a sweep, provision
Wi-Fi, create credentials, or automatically adopt a camera.

The first full discovery contract run exposed a cancellation race: the task
owner's requested cancellation was reported as `AuthorityStopped` where the
periodic scanner expected `Cancelled`. A first classification change then
failed the parked-discovery contract because the existing runtime check also
reports ordinary drain as cancellation. The task owner now exposes its own
explicit cancellation-request state separately. Discovery rechecks admission
before socket polls and before admitting a received candidate, classifies an
explicit task cancellation as `Cancelled`, and retains `AuthorityStopped`
when admission closes through normal drain. Parent and runtime cancellation
remain separately observed; no ordering between concurrent causes is claimed.

Strict-remote job `j-30110656841646338` built the final discovery contract on
`ts1`. The wrapper returned 102 after rejecting Linux-to-macOS executable
transfer; the worker build itself succeeded. In an isolated network namespace
with deletion syscalls denied, the contract target passed 17 tests; its two
owner-authorized real-LAN tests were ignored. The cross-page case exercised
six pages with more than 512 total datagrams, repeated and conflicting claims,
out-of-order pages, duplicate and missing pages, wrong scopes, incomplete
reports, and refusal to refresh a sweep fleet with one report. It also checked
that a previously ready entry becomes conflicted when a later complete sweep
contains a conflicting claim. The parked and periodic cancellation cases each
passed five additional repetitions. The two earlier 16-pass/one-failure runs
remain separate failed results; the second used the initial classification
that conflated drain and cancellation. Traces are retained under
`/data/tmp/fss-sweep-fleet-20261115-01` through `-03` and
`/data/tmp/fss-sweep-cancel-repeat-20261115-01` on `ts1`.
The final executable SHA-256 was
`147a3e10f230ac8cc5f30b904d1b21a4a8efd750fdba4d0350dabcb14293aae2`;
the local and worker runtime, discovery, fleet and contract sources matched.
The separately built runtime owned-execution contract passed 17/17 tests on
`ts1`; strict-remote job `j-30110656841646339` built it, and the wrapper again
refused foreign-artifact transfer after the worker build succeeded. Its
executable SHA-256 was
`f2846ede1c673f3bcdd8d206a573e919993bd1b5afcbea1dcd34098cf9493460`.
The final discovery, repeated cancellation and runtime traces recorded no
deletion attempts.

A separate read-only check on `trj` used the latest single-candidate discovery
report to inspect the existing controller's network namespace. It found two
established connections involving that candidate, one at the controller port
and one other. The controller's latest matching track-command log claimed the
medium track on the latter port. This is point-in-time socket and log evidence,
not independent device authentication or proof of the media format, and it
did not issue a camera request or settings change. The fallback recorder
remained active with six files modified in the preceding five minutes. No
live full-resolution Rust takeover, continuous native recording, automated
camera setup, crash recovery, or 30-day retention is established by this work.

### Task-owned paged sweep runner (2026-11-15)

The discovery runner now accepts a caller-owned plan of up to 17 pages, each
with up to four bounded windows. It retains individual reports and publishes a
fleet refresh only after all planned windows complete. A cycle is bound to one
fleet (or explicitly to no fleet), and refuses a change midway through the
cycle. An interrupted or incomplete window preserves observations and does not
refresh the fleet. The caller drives the runner and supplies authority and the
plan; these labels do not establish device identity or prove host coverage.

The opt-in `fss-unifi-discover --sweep-all` command drives a bounded planned
sweep and emits its constituent window reports. On an earlier source snapshot,
isolated synthetic peers exercised two single-page cases, two complete-sweep
cases including a cross-page claim conflict, and a packet-limit partial sweep.
The command's 14 option and planning tests and the other discovery command's
29 tests passed on that earlier snapshot. None was a physical-camera test.

Strict-remote job `j-30110656841646346` built the fleet-binding version of the
discovery contract on `ts1`. The build succeeded on the worker; its wrapper
returned 102 after refusing to transfer a Linux executable to macOS. In an
isolated network namespace with deletion syscalls denied, 21 contract tests
passed and two owner-authorized real-network tests remained ignored. The
runner and contract source SHA-256 values matched between the workspace and
worker: `4f718bbd0942334546651f8aa894404d0765659b7ceb2fbcb3ce86916f3239ad`
and `7a030a721f5dd66c03062e084e825defa6bb40bb9fbeae58be4b3164ac1d2f96`.
The trace is retained at `/data/tmp/fss-sweep-runner-final-20261115-01/trace`
on `ts1` and recorded no denied deletion attempts.

Strict-remote job `j-30110656841646347` subsequently built the command on
`ts1`; the wrapper again returned 102 for foreign-artifact transfer. The worker
binary SHA-256 was
`43ed6646aed4a5460964489f024e509bd6b3fb9f24eda4146903479ef5c560e1`.
The isolated fixture passed again with two single-page peers, two complete
sweeps including a cross-page conflict, and one packet-limited partial sweep.
Its deletion-denying trace at `/data/tmp/fss-sweep-all-e2e-20261115-02/trace`
recorded no denied deletion attempts. This did not contact the physical G4.

These changes do not install or schedule background scanning, provision Wi-Fi,
adopt cameras, settle the prior physical effects, establish direct live
high-resolution capture, or provide continuous recording and 30-day retention.

### Full-resolution evidence and fallback inventory (2026-11-15)

The previously documented passive high-track Rust still remained present on
`trj`, with its recorded SHA-256
`190ed6094175f7929cdbbacd17dd423228ba566a363e9c314080dc58d015dcf7`.
A hash-checked local copy measures 2688 x 1512. Its file modification time
was November 13, 2026, 19:51 EST; it is not a current live view. As documented
in `UNIFI_DIRECT_REFERENCE.md`, it was decoded by Rust from a passive copy of
the camera stream while Scrypted owned the connection, with synthetic startup
framing and an independently unverified codec epoch.

The retained five-second Scrypted-originated high-profile clip also matched
its recorded SHA-256
`2ce702b355fa7d8a56780a5dc881d3c0e68b5a21d2e9db7d0bd8b0cef6b55361`.
FFprobe reported H.264, 2688 x 1512 and 151 video frames. It was recorded
November 10 and is not evidence of a current Rust-owned camera session.
Both files were copied to private local files after checking their hashes; no
camera setting or recorder service was changed.

A separate read-only inventory of the fallback directory found 11,970 MP4s,
approximately 55.65 GiB, with the oldest modification time November 5 and
the newest November 15 UTC. A recent closed file contained 1280 x 720 H.264
video and no audio stream. These point-in-time observations do not prove
continuous coverage, 30-day retention, or future cleanup behavior. The
recorder was active with six files modified within five minutes.

### Paged discovery with routing and setup work (2026-11-15)

The caller-driven discovery coordinator now has a paged-sweep variant. It
drives a retained sweep window alongside the existing controller router,
caller-owned camera setup futures and retry queue. The runner, router and retry
queue must bind the same fleet, task and clock; the fleet must have the runner's
caller-labeled sweep scope. A partial window or refused refresh stops new
windows without replacing the last complete fleet view. A requested stop drains
the in-flight window and preserves the rest of the cycle. The caller continues
to own enrollment, credentials, setup construction, outcomes and effect
reconciliation. This is a composition primitive, not unattended setup.

Strict-remote job `j-30110656841646351` built the final discovery contract on
`ts1`; the build succeeded but the wrapper returned 102 after rejecting transfer
of a Linux executable to macOS. In an isolated network namespace, 23 tests
passed and two live-network tests were ignored. The new cases covered setup
completion and an unknown route while a sweep was in flight, fleet and scope
mismatch, stopping and resuming between pages, a completed refresh, and a
packet-limited partial window that leaves the prior fleet view unchanged.
The final test executable SHA-256 was
`813670b2c6c39d3ebe02aaddd750b3163bf27d9dd512f7d4eccc8e1417868b13`.
Its deletion-denying trace is `/data/tmp/fss-sweep-pump-final-20261115-01/trace`
on `ts1` and recorded no denied deletion attempts.

The first handoff test build, job `j-30110656841646352`, failed with two Rust
borrow errors in the new fixture. After correcting its owner-drop order, job
`j-30110656841646353` built successfully on `ts1` with the same wrapper 102
foreign-artifact refusal. The worker executable SHA-256 was
`aba3bef4d49fc97d5841e768ff390b4a348441c5f2821b82bba9b5fe9f0055bf`.
In a separate isolated network namespace, the new synthetic-camera test passed:
an actual setup attempt was denied before an effect, was not automatically
retried, and an explicitly scheduled retry timer rearmed its fleet entry. The
existing fleet-setup fixture also passed its three subcases. Their traces are
under `/data/tmp/fss-sweep-pump-setup-20261115-01` and
`/data/tmp/fss-sweep-pump-setup-regression-20261115-01`, with one and three
deletion attempts denied respectively. The workspace and worker copies of the
changed discovery, coordinator and test sources matched by SHA-256.

The new retry test did not exercise automatic scheduling of an eligible
transient failure. No physical camera or recorder configuration was changed;
the recorder remained active with six recently modified files. Automatic
camera enrollment, direct full-resolution recording, live effect reconciliation,
crash recovery and 30-day retention remain unproved.

### Paged sweep and protected automatic-setup laboratory (2026-11-16 UTC)

The protected controller acceptor can now serve as the paged sweep pump's
driver, with exact fleet, task-clock and runtime-context checks. The scoped TLS
laboratory's lease supervisor can drive that pump, select a ready owner-enrolled
camera, and retain a factory-provided setup future alongside discovery and
protected routing. It rejects an automatic-work owner for a different fleet
before invoking the factory. Enrollment, credentials, transport qualification,
effect authority and operation construction remain caller-owned. This new
laboratory path does not yet coordinate the existing automatic stream and retry
supervisors, and does not implement unattended onboarding.

The first strict-remote build (`j-30110656841646355`) failed because the
existing fleet fixture directly accessed a startup field made private by the
current listener API. A read-only startup accessor now preserves the test's
existing checks. The second build (`j-30110656841646361`) succeeded on `ts1`;
its wrapper returned 102 after rejecting a Linux executable on macOS. Its
first synthetic run failed before the new sweep case: the old synthetic camera
fixture did not answer the recently added status recheck, causing an EOF. The
fixture was updated to answer that request and to keep its pre-handoff stop at
the correct position. Strict-remote job `j-30110656841646365` then built the
final test; the wrapper again returned 102 for foreign-artifact transfer.

In separate private network namespaces, the deadline-recovery and the
full-resolution factory-stream synthetic TLS scenarios each passed 1/1. Each
included the new case: a camera already present in the owner inventory began
unobserved, a completed UDP sweep made it ready, the protected acceptor was
driven during discovery, a different fleet was refused before factory invocation,
and a stub future was selected and returned. The scenario's separate existing
path exercised synthetic TLS setup and, in the second test, a synthetic
2688 x 1512 factory stream. These checks do not prove a camera setup or TLS
handshake *through the new paged path*, a real camera connection, audio,
continuous coverage or retention. The fixture uses an explicit 16 MiB test
thread stack and is not normal-stack qualification.

The first failed run and both passing runs retained deletion-denying traces at
`/data/tmp/fss-sweep-auto-fleet-20261116-01` through `-03` on `ts1`, with one,
eleven and thirty-one deletion attempts denied respectively. The final worker
binary SHA-256 was
`f7d4df722011c162dd5f9b06630a6f0fd84c756dc6ea4b37d700523d95e874a4`;
the changed acceptor, listener, sweep, supervisor and fixture sources matched
the worker copies. The existing recorder was active with six recently modified
files, and its restart count remained eight. No physical camera configuration
was changed; the earlier physical effects remain unresolved.

### Two-page sweep through actual synthetic setup and controller (2026-11-16 UTC)

The paged-sweep TLS fixture now uses the laboratory's camera-specific factory
instead of a placeholder future. Its owner-enrolled synthetic camera starts
unobserved. Two UDP discovery windows must complete before its fleet state
becomes ready; the fixture checks that the first page alone does not select the
camera. The factory then creates its pinned TLS camera session and tracked setup
attempt. A separate synthetic camera peer returns through the paged pump's TLS
and WebSocket controller acceptor, and its MAC claim matches the enrolled
camera. The fixture checks that the setup attempt's entropy worker drained and
its separate effect journal retains the committed synthetic operation. This
is a laboratory scenario, not settlement of that operation or independent
identity proof.

Strict-remote job `j-30110656841646368` built the final test on `ts1`; its
wrapper returned 102 after refusing Linux-to-macOS artifact transfer. Both the
deadline-recovery and full-resolution factory-stream synthetic TLS scenarios
passed 1/1 in separate isolated network namespaces. Each included the new
two-page discovery, real setup-factory work and protected controller session.
The full-resolution video stream belongs to another existing portion of the
same scenario, not to the newly accepted paged controller session. The test
thread uses a 16 MiB stack. Final fixture source SHA-256 was
`afcfb293e7a8a55178b13b8d634880be42bf8075ed79aff1d459589aa4f388c7`
and the worker executable SHA-256 was
`3f8a87ad2f0ad9c6b2cf7bb488f482d690bbb667582e4e8b982dba75f8ec0fe7`;
the source matched both the original checkout and the prepared worker input.
The two passing traces are under `/data/tmp/fss-sweep-factory-two-page-20261116-01`
and `-02` on `ts1`, with eleven and thirty-one deletion attempts denied.
Earlier one-page versions also passed separately and remain under
`/data/tmp/fss-sweep-factory-real-20261116-01` and `-02`.

No physical camera or recorder configuration changed. The existing recorder
was active with six recently modified files and eight restarts. The paged path
still requires owner-supplied enrollment, credentials and setup plan, has not
been connected to its own automatic stream/retry supervisor, and has not been
tested as a direct physical-camera session. Full-resolution native recording,
continuous service, independent reconciliation and 30-day retention remain
unproved.

### Paged sweep through synthetic full-resolution recording (2026-11-16 UTC)

The scoped TLS laboratory supervisor now composes the paged sweep and setup
path with retained stream work. It checks the fleet and transport bindings,
refuses simultaneous setup and stream work for one enrollment, retains refused
sessions and unpolled work, and requires explicit disposition of completed
stream effects. An accepted session may be passed to a caller-supplied stream
factory with the setup-time reported profile. This new path does not yet drive
the existing retry coordinator or automatically enroll unknown devices.

In the updated synthetic scenario, two discovery pages complete before the
owner-enrolled camera becomes ready. The camera factory performs pinned TLS
setup, the same synthetic camera establishes its protected controller session,
and the paged supervisor admits that session to the existing stream factory.
The factory starts media, writes and reopens source and video archive records,
checks source-byte coverage, and decodes at least one frame. In the
full-resolution run it verifies the selected video1 claim and decoded picture
dimensions of 2688 x 1512. The scenario also refuses a different fleet and a
simultaneous setup/stream overlap before polling their work; a completed stream's
unsettled effects prevent release. Media and cameras are synthetic, the test
uses a 16 MiB thread stack, and this result does not prove physical capture,
audio, unattended service, independent durability or retention.

Strict-remote job `j-30110656841646370` built the final fixture on `ts1`.
The worker build succeeded, and the wrapper returned 102 after refusing a Linux
executable on macOS. The final full-resolution and standard deadline-recovery
scenarios each passed 1/1 in separate network namespaces. Their deletion-denying
traces are `/data/tmp/fss-sweep-stream-final-20261116-01/trace` and `-02/trace`
on `ts1`, with 46 and 16 deletion attempts denied. The final supervisor and
fixture SHA-256 values were
`a6413864b390cd7444f157b75fba24e60cdc7a897e708f8f309fb6fcda677838` and
`8c4ec4fdf050f12a2995f1205e0a7cbb341794e059dea37498f888e31ab14505`,
matching the workspace and worker copies. The worker executable SHA-256 was
`2118fd040904e6e0b3047a94fd49acb2281534287a44389c778fe00e3dc26a81`.
An earlier full-resolution version also passed under
`/data/tmp/fss-sweep-stream-synthetic-20261116-01`; it preceded the added
fleet-mismatch and overlap checks.

No real camera setting was changed. The existing recorder remained active
with six recently modified files and eight restarts. Direct live camera capture,
prior effect reconciliation, automatic retries on the paged stream path,
unattended operation and 30-day retention remain unproved.

### Paged retry integration and validation (2026-11-16 UTC)

The scoped TLS laboratory source now composes the paged setup/stream owner
with its retry coordinator. It checks the exact queue, fleet, transport and
task bindings before polling; an exact fleet-classified transient pre-effect
failure can schedule a timer, and a matching rearmed timer can release the
selection latch for a fresh caller-owned setup attempt. Original completions,
stream refusals and unresolved effects remain caller-owned. This is a
laboratory path and has not been deployed.

The synthetic fixture was extended to close its first TLS login connection,
expect an automatic pre-effect retry with no effect-journal entry, and then
perform a distinct successful setup, protected stream and archive. The source
and prepared workspace copies matched, and rustfmt parsed both changed Rust
files. Strict-remote test-build request `9253482693696421903` was queued on
`ts1` at this handoff; a queued request is not a successful build or a test
result. No new physical camera request or recorder configuration was made.

The queued `ts1` request subsequently timed out before admission with
`RCH-I001`/103. A separate `hz2` request (`j-30110656841646375`) was refused
before source or execution grant because its destination was a live checkout;
the checkout was not modified. Strict-remote job `j-30110656841646376` then
built on the isolated `hz4` mirror. The worker build succeeded; the wrapper
returned 102 after refusing to transfer a Linux executable to macOS.

The final standard and full-resolution synthetic TLS scenarios each passed
1/1 in separate isolated network namespaces. Both ran the two-page sweep, a
first login connection that closed before an effect, exact automatic timer
admission and rearm, a distinct successful setup attempt, protected controller
connection and archive/decode. The full-resolution case decoded a 2688 x 1512
synthetic picture. The fixture also checks a different retry queue is refused,
the first operation has no journal entry, and successful setup is not retried.
It does not establish real camera behavior, automatic enrollment, audio,
continuous coverage or 30-day retention; the test uses a 16 MiB stack.

The supervisor and fixture hashes were respectively
`f26f139822ef5c811622ee805c07f99ef42470f4c3cb90deb035b53780b4b2f4` and
`c3a93fad925993fe98ac2e766cb8dfef49d79cd84626cc1660ceff90f45f19d3`,
matching the workspace and worker. The worker executable SHA-256 was
`96cb5661bcffa0bcff3ab5aed4e6b5eec0eb34c65d172d01bb9eeacf84a2c6a4`.
The deletion-denying traces on `hz4` are under
`/data/tmp/fss-sweep-retry-hz4-20261116-01` and `-02`, with 16 and 46
attempts denied. The existing recorder remained active with six recently
modified files and eight restarts; no physical camera setting changed.

### Paged camera factory with synthetic audio/video (2026-11-16 UTC)

The scoped TLS laboratory now exposes a caller-driven entry point combining
the paged sweep, exact owner-bound camera factory, retry coordinator and
routed stream factory. A factory bound to another fleet is refused before
work is polled. This is a library entry point, not an installed CLI or
unattended recorder; enrollment, credentials, effects and shutdown remain
the caller's responsibility.

The final synthetic fixture uses that entry point after two discovery pages.
Its first camera login closes before an effect; the automatic retry creates
a fresh operation, performs setup and accepts the same synthetic camera's
protected controller session. That session supplies full-resolution video
and synthetic AAC-framed audio to the Rust archive path. The fixture reopens
audio/video records and decodes video pictures at 2688 x 1512. A separate
scenario crosses a configured archive-capacity boundary and resumes in a
successor generation. The audio payloads are synthetic and were not decoded
or played; the test does not establish audible audio or synchronization.

Strict-remote job `j-30110656841646378` built the final fixture on `hz4`;
the worker build succeeded while the wrapper returned 102 after rejecting
Linux-to-macOS artifact transfer. The full-resolution synthetic audio/video
and audio/video-rollover scenarios each passed 1/1 in separate isolated
network namespaces. Their deletion-denying traces are under
`/data/tmp/fss-paged-av-20261116-01` and
`/data/tmp/fss-paged-av-rollover-20261116-01` on `hz4`, with 24 and 26
deletion attempts denied. The supervisor and fixture SHA-256 values were
`7f2b2aa154cbcb447dd3b4c37d67e5cbb5b317e06cbd3c65b410b73f9569699a` and
`597684ceb17021f667e75bbaf78b865b3454cda65703be206d117f7c54f62a5b`,
matching the workspace and worker. The worker executable SHA-256 was
`a99571aae99c4f52e35125ac68a27a669a2b4b38af8b7610deab26322587cd70`.
The fixture uses a 16 MiB test thread stack; source custody and local readback
do not prove crash recovery, independent replication or physical identity.

No physical camera setting changed. The existing recorder remained active
with six recently modified files and eight restarts. Direct live G4 capture,
automatic enrollment, an operational service and 30-day retention remain
unproved.

### All-page discovery into the executable setup path (2026-11-16 UTC)

The laboratory trial executable now accepts `--lab-discovery-sweep-all` after
`--discovery-neighbor-interface=NAME`. It requires automatic discovery, an
independently checked interface and a /20 through /30 scope, and refuses a
separate discovery hint in that mode. The shared host planner generates
bounded pages, which the caller-driven sweep combines before the existing
selection and certificate-pin checks. An incomplete page cannot reach setup.
The existing persistent camera fence and anchored-journal requirements apply
unchanged. The existing discovery CLI now uses that same planner. A target
plan or a matching certificate remains an operator-scoped claim, not proof of
physical identity, complete network coverage or authority to enroll devices.

The planner test passed 1/1 on `hz4`, checking every supported subnet size,
both broadcast policies, first and last interface positions, complete host
coverage without duplicates, and invalid scopes. The trial executable on
`ts1` passed an isolated fixture with a synthetic camera on the last address
of a /24: two pages, five windows, a certificate-only probe, and read-only
profile observation. A separate trial of the same path with a pre-existing
synthetic fence stopped before credentials or camera setup, as expected.
The existing discovery CLI regression also passed its two single-page cases,
two all-page cases including a cross-page claim conflict, and one packet-limit
case that retained the partial report without accepting the sweep. Its trace
is retained under `/data/tmp/fss-sweep-cli-shared-20261116-01` on `hz4`.

A further isolated fixture drove discovery, synthetic pinned setup and a
controller session into three archived video segments across two generations;
Rust reopened the archive and decoded two synthetic 2688 x 1512 frames. Its
setup effects remained unsettled. An initial variant stopped its child before
a completion receipt and failed; a second completed the archive but failed a
five-frame assertion, having decoded two frames. The final fixture used the
existing high-resolution fixture's two-frame threshold and passed. These are
synthetic test results, not live capture, audio, independent physical identity,
crash recovery or continuous service proof.

Strict-remote jobs `j-30110656841646387`, `j-30110656841646389` and
`j-30110656841646391` built the reference tests, trial executable and
discovery CLI on Linux. Each worker reported build success; each wrapper
returned 102 because it refused to transfer a Linux executable to macOS.
Planner, trial and CLI source SHA-256 values were respectively
`60daf06e7ab2dd563df7c63e3b069e69f0def4846781fc67d0afc7cdc1f4e40f`,
`50f1c64b6901b69edc60f42f286da9861187aa62168e1a05c14c72647dd6b741` and
`b945c108604bf0d115addc793ee0771977db3936738ce89ac1ad0f207d972be3`.
The `ts1` trial binary SHA-256 was
`a4edce1867a726966118c51b12a8c9272f4e45a7b1d0d1dc12aa027d47e9c47e`.
The isolated test traces are retained on `ts1` under
`/data/tmp/fss-trial-sweep-pin-20261116-01` and
`/data/tmp/fss-trial-sweep-setup-20261116-01` through `-03`, and on `hz4`
under `/data/tmp/fss-sweep-host-plans-20261116-01`. Deletion syscalls were
denied during these tests. No physical camera was contacted; the previous
physical fence and unresolved camera effects remain in place.

### Real-camera all-page observation and checkpoint drift (2026-11-16 UTC)

The `ts1` all-page trial executable from the preceding section was copied
create-only to `trj` and hash-matched. A single owner-authorized read-only
run selected the existing `eno1` /22 scope, completed five pages and 17
windows, and matched one discovered candidate against the previously retained
camera certificate before sending credentials. Two adjacent serializer reads
matched each other, and the peer reported a 2688 x 1512, 30 fps high profile.
Rust decoded its snapshot at 640 x 360 without persisting media. The camera
certificate and network claim are not independently verified physical identity.

The current serializers were compared to the encrypted restored checkpoint
from the prior physical trial. The comparison returned `OtherTracks` with
`target_changed=false`: at least one non-target track differed, while the
original target track matched that checkpoint. The prior requested fields did
not match the current target. This is a current claim, not proof of who changed
the other track, when it changed, or the outcome of either earlier operation.
It means that the old checkpoint must not be applied as a whole to current
settings. The two earlier committed effects remain unresolved, and the fence
was not altered. No camera setting write was issued in this run; login session
expiry is unknown. The trace in
`/data/unifi-g4-recorder/fss-sweep-observe-20261116-01` recorded no denied
deletions and no trial journal or output was created. The fallback recorder
remained running with eight restarts and six files modified in five minutes.
The already-installed fallback and USB upload scripts both configure 30-day
aging for matching completed MP4s; their timers were active and their latest
reported service results were successful. This source and point-in-time service
inspection does not prove 30 days of coverage or that a 30-day deletion has
actually occurred. No timer or retention setting was changed by this check.

### Durable restore-response claim (2026-11-16 UTC)

For future experimental HTTP restore attempts, a complete HTTP 200 response
is now bound to the exact preparation and its bounded, payload-free response
shape by a domain-separated digest. After task and storage admission, the
existing effect journal records that digest in `AdapterAccepted` before the
follow-up readback. A cancellation, authority refusal or journal failure
retains the permit and response for reconciliation; a lost or non-200 response
does not create the acceptance transition. An HTTP 200, its body shape and
same-session readback remain peer claims: the operation is still unresolved,
and this receipt grants neither a retry nor fence release. The fence inspector
reports whether the current restore acceptance state has a digest, without
printing serializer values or treating the digest as independent proof.

The response-binding unit test passed 1/1 on `hz4`. A separate isolated
synthetic-camera fixture passed 5/5 cases on `ts1`: normal restore, a 200
response followed by an ignored restore, a lost response, failure restoration
after invalid video framing, and A/V restoration. Cold inspection distinguished
the acknowledged but ignored effect (`AdapterAccepted`) from the lost response
(`Committed`); neither was verified. The original physical trial predates this
record and cannot acquire a response retroactively. No physical request was
made, and the pre-existing physical fence remains unchanged.

The existing isolated restore regression also passed 20/20 synthetic-camera
cases and its option-refusal check, covering changed tracks, short streams,
accept timeouts and video/A/V failure restoration. Its deletion-denying trace
at `/data/tmp/fss-restore-receipt-regression-20261116-01` on `ts1` recorded
43 denied attempts. The regression fixture SHA-256 was
`9990043425a6e6a1075d4704ef67286b86ca1f8aba3ccac406acfe982dc28f7f`.

The first synthetic fixture invocation stopped before camera discovery because
the namespace lacked its required neighbor entry; no effect was prepared. A
second private namespace supplied the synthetic neighbor and passed. Strict-
remote jobs `j-30110656841646400` and `j-30110656841646403` built the test
harness and executable on Linux. Both worker builds succeeded; their wrappers
returned 102 after declining Linux-to-macOS artifact transfer. The unit and
fixture traces are retained under `/data/tmp/fss-restore-receipt-unit-20261116-01`
on `hz4` and `/data/tmp/fss-restore-receipt-e2e-20261116-02` on `ts1`; the
latter recorded 18 deletion attempts denied. Restore code, fence inspector,
shared fixture and runner SHA-256 values were respectively
`613910126912d862e76d871e4e119c47cf1b9a7a4ce6538e2b04bb38be50a849`,
`48694b848a90a81dd95fb87a3e577d45e7af1223927c05dcc3b5e736c8db2eee`,
`3089cf2df76aaa2f3133e088ed40c8039d3d7034394a2de935e7b151f8545b28` and
`869bc9947019ece13dc1bcdfb7a0b41c6785ea2599efb38589f3501b4d4bef98`.
The `ts1` executable SHA-256 was
`fff3554e02e028fb64f1ee335ec79f905b1aaed763f9e71fd06a93b9197676c7`.
The existing recorder was running with eight restarts and six recent files.

### Durable start-response claim (2026-11-16 UTC)

The experimental checkpointed video and A/V start paths now record the
camera's bounded HTTP 200 response shape in the effect journal before the
serializer readback and media accept. The start and restore response digests
use distinct domains and bind the full prepared operation. A response-custody
failure returns the original permit and redacted observation and stops before
readback; it does not trigger automatic restoration or retry. A successful
response remains an untrusted peer claim, not independent verification, and
both effects still require reconciliation. Existing callers that do not opt
into response custody retain their earlier behavior.

The final isolated library executable passed 4/4 targeted tests on `hz4`:
custody failure stopped before readback with the committed permit retained;
checkpointed video and A/V starts recorded the exact expected digest and
reopened the same digest from the journal; and an existing no-custody caller
retained its original committed state. These tests used a 32 MiB test stack.
The standalone synthetic-camera trial passed five focused restore cases,
two start/readback cases including an acknowledged but unapplied start, and
20/20 restore regressions plus an option-refusal check. The first video and
A/V test attempts failed because an old cold-recovery assertion still expected
`Committed`; the final tests assert `AdapterAccepted`, its exact digest, and
continued unresolved status. No actual camera was contacted.

The first standalone build request timed out in the `ts1` queue without
admission. Strict-remote `j-30110656841646411` built the executable on `hz4`,
and `j-30110656841646414` built the final library test there. Both Linux worker
builds succeeded; their wrappers returned 102 after rejecting Linux-to-macOS
artifact transfer. The final executable SHA-256 was
`6d09c84a6098d9748a7e35c8e7633c2a785d237e91c8169fed5e2b19f28b340e`;
the library test executable was
`13c671efbf5268393820efc978ce0e529289dce56bdaf0818ead48ef2a5e5a09`.
Final deletion-denying traces are under `/data/tmp/fss-start-receipt-final-20261116-01`
through `-04`, `/data/tmp/fss-start-receipt-e2e-20261116-02`,
`/data/tmp/fss-start-receipt-readback-20261116-01` and
`/data/tmp/fss-start-receipt-regression-20261116-01` on `hz4`. The final
regression trace recorded 43 denied deletion attempts. The receipt callback
is synchronous and its journal persistence has not been qualified against
runtime blocking or cancellation during filesystem I/O. It is not an
unattended service, physical-device handoff, independent effect settlement,
or 30-day retention proof. The old physical fence remains in place and the
fallback recorder was running with eight restarts and six recent files.

### Read-only device inspection (2026-11-16 UTC)

A network-discovered, certificate-pin-selected camera accepted its existing
local account over SSH. The account had root privileges; its SSH host key was
recorded on first observation, not independently authenticated. At inspection
time its network listeners were ports 22, 80 and 443, with no direct RTSP
listener. Its processes included a native streamer, and a local Unix socket
was associated with that streamer. No camera settings were changed and no IPC
request was sent. SSH access itself can produce device audit or log entries.

Static inspection of bounded, read-only copies of the device's ARM binaries
found an IPC client and JSON message fields. Disassembly suggests a four-byte
big-endian JSON length prefix, but neither actual IPC traffic nor a read-only
video subscription was verified. The socket may be control-only. A bounded
log sample did not establish the outcome of the earlier effects; automatic
command review rejected a more detailed log inventory. The physical setup
fence and both unresolved effects remain in place. This inspection is not a
working native stream, independent device identification, or permission to
retry a camera settings change.

### IPC diagnostic-client constraint (2026-11-16 UTC)

The camera's previously copied `libubnt_ipc.so` has SHA-256
`8f2377a7e515ce8aab3622ac4678d0ba94f0c0486a956c84bdd3ccef719b35ca`;
the copied `ubnt_ipc_cli` has SHA-256
`a0f6fb7001c250b7da30c997b3b08ceb8c6f67496059a5d68acacc0552947d15`.
Thumb-mode static disassembly of that library shows that `Ipc::Init` can
construct and initialize an `IPCIOAcceptor`, and the acceptor initialization
calls `unlink` before creating its socket. Its destructor also calls `unlink`
when a socket path is present. The client imports `Ipc::Init`; the precise
branch and paths selected by a given invocation have not been dynamically
verified. Therefore the vendor client must not be run on the physical camera
under the operator's no-deletion rule merely because the requested IPC
function sounds read-only. A fresh, pin-checked SSH tool inventory found no
`strace`, Python 3, or `socat` executable on the camera's PATH; it did find
`nc` and `timeout`. No CLI or IPC request was executed.

A published security analysis of a different UniFi camera includes a vendor
support-script invocation of `GetVideoSettings` against `ubnt_streamer`
(https://blog.compass-security.com/2025/06/pwn2own-ireland-2024-ubiquiti-ai-bullet/).
That supports investigating a diagnostic read, but does not establish this
camera's exact behavior, independent serializer-effect settlement, a safe
client lifecycle, or access to a video stream. A future investigation needs a
bounded, isolated protocol fixture and a transport that cannot unlink camera
files before contemplating a device request. Do not substitute a settings
change or bypass the existing effect fence.

The fallback recorder was active with eight cumulative restarts and six files
modified in the preceding five minutes. `/bulk` reported approximately 3.2 TiB
available at inspection time; available capacity is shared and is not a
30-day retention or continuity guarantee. The recorded credential rotation
and factory-credential rejection on 2026-11-05 remain historical evidence; the
currently protected replacement was accepted during this inspection, but the
factory credential was not retested.

### Isolated diagnostic protocol and forwarding probe (2026-11-16 UTC)

On `trj`, the physical camera's diagnostic client and its transitive ARM
shared libraries were copied read-only into a root-only laboratory chroot at
`/data/tmp/fss-unifi-ipc-lab-20261116-01`. QEMU executed the client inside
that chroot with separate Linux network and IPC namespaces. A synthetic Unix
socket server supplied all responses; it had no physical camera connection.
Host-side traces denied `unlink`, `unlinkat`, and `rmdir`, and recorded no
denied calls in these trials. The firmware binaries are laboratory oracles,
not production dependencies.

The client sent a four-byte big-endian length followed by its ASCII endpoint
name, then a second length-prefixed JSON request. A synthetic correlated
`__response__` JSON frame sent back on that same connection, without a second
name handshake, produced client exit 0. Sending an extra name handshake instead
caused an invalid-JSON error and timeout. Changing `requestId` caused timeout;
changing the response's `from` to a different synthetic name while preserving
the request ID still produced exit 0. This last observation demonstrates that
the vendor client did not reject this particular mismatched sender claim; it
does not establish a network authentication boundary. These are synthetic
server results, not a response from the camera's real `ubnt_streamer` and not
a demonstrated video subscription. The reproducible fixture scripts
`observe2.py`, `observe5.py`, `observe6.py`, and `observe7.py` in that private
directory have SHA-256 values, respectively,
`f2466185cf3c6859a4117e50340354763361edbd6301538479550ff1e31f1e5e`,
`28d6d373611699e7f2fd9086ac1df14b58347103a8f1f2b0b9a42bbf5222c580`,
`16d59c71d185d8a0540306abd3314c782ae25c277b6b694c906d94fe29c8c924`,
and `fc8207d50e8f575c7b7e62371c42de2de6d6213c277e4de17fba0a508315eba3`.

One bounded, settings-only physical probe attempted SSH forwarding to the
camera's existing streamer socket after fresh scoped discovery, a retained
HTTPS certificate comparison, and a strict SSH host-key check. The local
connection reset without a response. A separate forwarding-only check sent no
IPC message and identified an SSH channel-open failure with an unknown-channel
indication; the camera SSH server did not provide the requested stream-local
forwarding. Thus the probe did not establish delivery to the streamer or
obtain settings. Camera `nc` lacks Unix-socket support, and its curl reports
only file, HTTP and HTTPS protocols without the UnixSockets feature. No camera
diagnostic executable was run and no camera settings were changed. The SSH
host key remains trust-on-first-observation rather than independent identity.
The two earlier effects and the physical fence remain unresolved. The local
SSH traces denied deletion syscalls and recorded no denied calls; the fallback
recorder remained active with eight cumulative restarts and six recent files.

### Bounded Rust diagnostic framing (2026-11-16 UTC)

The experimental `unifi_direct::ipc_diagnostic` reference module encodes a
non-queued `GetVideoSettings` request and the observed name handshake, parses
bounded length-prefixed frames, and strictly checks the response name, sender,
recipient, and exact request ID. Strict JSON parsing rejects duplicate keys;
debug formatting omits returned settings. The owner supplies the name, ID,
timestamp, authority and transport. These checks preserve peer claims without
authenticating the peer, establishing physical identity, settling effects or
granting a retry. No async owner, Unix-socket bridge or physical streamer
compatibility is implemented or proven by this module.

The exact module SHA-256 was
`a1726a783835b0e9be095df8d6a4efc9cd9888f8593ec9697004430d1e77b96b`
on the workspace and Linux worker. Strict-remote job
`j-30110656841646422` compiled the test executable on `hz4`; its wrapper
returned 102 after rejecting Linux-to-macOS artifact transfer. The exact
worker executable SHA-256
`46727e3d336ba457dbd37510eee1963758ed285e68d5e7e5a50b0d74ea134a6d`
then passed 4/4 focused tests under a deletion-denying trace at
`/data/tmp/fss-ipc-diagnostic-test-20261116-01/test.trace`. These are
reference and synthetic protocol tests, not a camera or service test. Rustfmt
check passed. The fallback recorder remained active with eight cumulative
restarts and six files modified in five minutes. The physical fence remains
in place and the goal of native recording without Scrypted remains open.

### Vendor-listener request compatibility (2026-11-16 UTC)

A second private QEMU chroot on `trj` ran the copied firmware diagnostic
client in its server/listen mode, with separate network and IPC namespaces.
The initial two attempts failed before listener startup because the chroot
lacked `/var/lock`; creating that directory in the private lab allowed the
third attempt to start. The synthetic client sent the exact name handshake and
JSON request now asserted in the Rust framing test. The vendor listener printed
the expected request object, confirming that this specific listener parsed the
synthetic request. It sent no response before the bounded timeout, so this is
not proof of the firmware streamer's reply schema or physical compatibility.
It does not establish access to media or effect reconciliation.

The fixture at
`/data/tmp/fss-unifi-ipc-server-lab-20261116-01/interop.py` had SHA-256
`b163dc2dc77e2f2f24fe97125a3761a9ac927a9ce573b11aa31a4bf8bb66720f`.
Its `interop3.trace` retained two deletion syscalls denied with `EPERM` for
the lab socket; no deletion was permitted. The actual camera was not contacted
by this listener test. The fallback recorder remained active with eight
cumulative restarts and six files modified in five minutes.

### Task-owned diagnostic I/O (2026-11-16 UTC)

The experimental `ipc_diagnostic_io::Owner` attaches a caller-admitted
`MeteredIo` to the exact task, runtime clock, resource, peer claim and camera
status authority. It rechecks authority on each read, write and flush, applies
one deadline and bounds the frame before allocation. An attempted exchange
spends the owner, including on refusal, timeout or cancellation; it cannot
reuse the transport. The raw response buffer is cleared on drop. The caller
still owns peer authentication, connection creation, final transport closure
and the returned parsed data. This is not an SSH implementation, Unix-socket
bridge, independently authenticated camera, effect reconciliation, or video
capture. No physical camera was contacted by the transport test.

Strict-remote job `j-30110656841646424` compiled the framing and transport
tests on `hz4`; their worker executables passed 4/4 framing tests and one
native loopback transport test. The latter includes successful fragmented
response receipt, pre-dispatch authority refusal, and dropping a pending
response future while retaining a spent owner. A later test revision also
checks authority revocation after four request bytes and refusal of an
oversized response header. Strict-remote job `j-30110656841646426` compiled
that revision, whose exact worker executable SHA-256 was
`f1d326193ae1acc8aa001e03e8de0e1a566599c024c69b0c769ec9f11256ab90`;
the one test passed with all of those assertions under a deletion-denying trace
at `/data/tmp/fss-ipc-diag-io-20261116-02/test.trace`. No deletion was denied
in that test. The checks use a real local TCP socket and synthetic peer; they
do not prove Unix-socket behavior, actual device behavior, explicit runtime
cancellation, or service-level shutdown. Both worker builds succeeded; the
RCH wrappers returned 102 because Linux artifacts were not transferred to the
macOS host. Rustfmt check passed. The fallback recorder remained active with
eight cumulative restarts and six recent files.

### Preserve pending source in a seeded successor (2026-11-16 UTC)

The source worker now provides `copy_pending_to_seeded_store`, a bounded
synchronous operation for a region-owned blocking worker. Given the previous
verified seed copy and both exclusively owned stores, it rechecks the journal,
keeper, ledger, retention, camera claim, destination capacity and seed graph;
it then publishes the still-held original record or batch to the successor and
reads that exact source graph back. The original pending input remains with the
predecessor on every outcome. A failure after publication retains the actual
receipt for reconciliation; a changed destination cannot be retried as if it
were still a fresh seed. This copy does not activate the successor, retain an
independent cross-store switch or recovery inventory, establish storage-failure
independence, settle camera effects, or prove 30-day recording.

The focused storage-capacity test passed 1/1 on `hz4` with 13 tests filtered.
It filled a one-root predecessor, retained a two-record pending batch, copied
the confirmed seed to a separate two-root store, refused wrong-camera,
insufficient-work, stale-head and withdrawn-retention cases before changing
the destination, then copied and independently read both pending byte ranges.
It reopened the successor from explicit in-process journal and keeper minima
and read the batch again. It also checked a single original record, and forced
read authority to be withdrawn after pending publication: the error retained
the actual receipt and the old pending batch. This was a synthetic storage
test, not an actual process-crash or independently retained cross-store-switch
test. The network namespace excluded the physical camera; the trace at
`/data/tmp/fss-pending-copy-test-20261116-02/test.trace` recorded 11 denied
deletion attempts.

Strict-remote job `j-30110656841646434` built the final test on Linux; its
wrapper returned 102 after declining Linux-to-macOS artifact transfer. The
executed worker test SHA-256 was
`08df25d62815c2d2b95216f5e97b2675d35da829a9d6d87d57b32ba824336cb9`.
The worker and workspace source/test SHA-256 values matched respectively
`8393983f542c1b8fff14081c7d94b91598d3324a9c02b6e13103f6663ff12f82` and
`aeef39de0543bb30275c51e0f987d5c4ad77038ee0fa5f879044ebb1ed3b14ab`.
An earlier test revision failed to compile after the successor was moved for
reopening but still referenced by its old variable; the final test retains the
reopened owners instead. `git diff --check` passed for the changed source and
test. The fallback recorder remained running with eight cumulative restarts
and six files modified in five minutes. The physical effect fence remains.

### Correction to the preceding pending-copy result (2026-11-16 UTC)

Subsequent runs of the rebuilt storage test refused before the wrong-camera
case because the blanket orphan check encountered the already-published seed's
temporary root file, whose cleanup had been denied by the test guard. The
earlier 1/1 executable result remains a historical observation, but its
reported source hash and post-build worker hash do not establish that the
executable actually included that exact orphan check. Therefore the preceding
entry overstates the evidence tying that pass to the stated source snapshot.
The failure is retained under `/data/tmp/fss-cross-switch-20261116-01` through
`-04` on `hz4`; it is not relabeled as a pass. The implementation now checks
the pending candidate's exact temporary slot before preparing an intent,
while retaining unrelated temporary files. The revised implementation and its
separate collision test require their own terminal build and test evidence.

### Retained cross-store candidate and explicit replay (2026-11-16 UTC)

The source worker now has an inactive cross-store switch candidate. Before
retaining it, the code rechecks the predecessor and successor source graphs,
camera and retention claims, the seed's confirmed successor-journal prefix,
both current journal and keeper heads, both ledger anchors, and digests of the
local store path spellings. A dedicated pin-retained journal stores the binding
and is rechecked against its retainer. A failed append or post-append check
leaves the predecessor fenced in memory and the stage spent; it cannot be
blindly retried. The separately retained switch can be reopened and inspected.
Path digests are local claims, not proof of physical storage independence.

After reopening a store, the exact confirmed source must first be replayed
through its existing anchored publication path. The new replay helper requires
the same journal and keeper heads and an already-ledgered receipt. A subsequent
candidate verification checks the retained switch before and after reading the
three relevant source graphs and rechecking both stores. This is not an atomic
multi-store snapshot, active-successor selection, a complete inventory of
competing switches, a durable inventory of store locations, or a process-crash
test. In particular, the in-memory fence does not survive a crash by itself.

The corrected pending-copy preflight admits an unrelated retained seed temp,
while refusing a temp at the exact pending candidate slot before journal intent.
On `hz4`, three separately isolated storage tests passed 3/3: the full-store
copy and retained switch/reopen/replay case; a failure injected after the
switch pin was durably retained, including spent-stage and in-memory-fence
refusal; and a candidate-slot orphan refusal before intent. The first case
also read back a single source and batch and checked the post-publication
receipt on read-authority withdrawal. These are synthetic storage tests, not
camera, unattended service, or 30-day retention qualification. Their traces
under `/data/tmp/fss-cross-switch-20261116-08` through `-10` denied 11, 4,
and 4 deletion attempts, respectively.

Strict-remote job `j-30110656841646468` built the exact Linux worker test;
its wrapper returned 102 because the foreign executable was not copied to the
macOS host. The executed worker binary SHA-256 was
`bff7a408c5a5010e7212eeeb7766c30940ede76a849e9cf097cd76917a844f56`.
Worker and workspace hashes matched for the source worker
`3f5ba6de4882142d2809def6026e82f16cf1c73640d9acb6b85f6c3ecfd616a9`,
cross-store module `c0f6a0bda02165a012179ed6a494ea8450fffcf2dc12772f78b7803c61206e8b`,
archive module `0715a6b6d2bef285a7a825b29c25fe78c5ac445748785813b58158d5cabe83b7`,
and test `f20498d285a6416cc0bc846c3b2104c765172a0c0d24a9a6dd34c8521440bc3d`.
The binary contained the new replay symbol, and the focused tests executed it.
Rustfmt passed for the new module and `git diff --check` passed for the changed
tracked files. The existing fallback recorder remained active, with eight
cumulative restarts and six files modified in five minutes. The physical
camera-effect fence remains unresolved.

### Separate-process cross-store reopen (2026-11-16 UTC)

The synthetic capacity fixture now has a fresh-process recovery case. After
retaining the candidate switch, the parent drops both archive owners and the
switch. The child receives only the fixture root path, opens the retained
switch pin from storage, inspects the switch for the two archive bindings and
heads, and reconstructs both stores from their known fixture locations. It
requires exact-source replay of both reopened stores before verifying the
switch and reading the two-record successor batch. Verification before replay
and with an altered switch head is refused. The child checks the fixture camera
and retention claims against independently specified fixture constants.

Strict-remote job `j-30110656841646471` built the test on `hz4`. Its wrapper
returned 102 after rejecting the Linux artifact transfer to macOS; the worker
build itself succeeded. The exact Linux executable with SHA-256
`f96596f97e3bb190e968e9daab7f343b1cd0c089158914a312df64e59b371793`
passed the fresh-process case 1/1, and the three related storage scenarios
passed 3/3 separately. The workspace and worker test source hashes matched
`93b97b2bd509a3df9f87230c48b23d026ca41c9a72a67fd12d1f61d0bfc60992`.
Each test ran in a separate network-isolated scratch directory under
`/data/tmp/fss-cross-restart-20261116-01` through `-04`; their traces recorded
7, 11, 4 and 4 denied deletion attempts, respectively.

This is a clean owner-drop and new-process synthetic test, not a forced crash,
power-loss test, independent storage-failure proof, discovery of competing
switches, or an unattended worker activation. The child knows the fixture's
store paths and scope; production still needs a trustworthy persistent
inventory and a fail-closed selection and activation protocol. Neither this
test nor the retained switch settles the earlier physical-camera effects.

### Physical diagnostic client invocation and rule violation (2026-11-16 UTC)

Two bounded `GetVideoSettings` invocations of the camera's existing
`ubnt_ipc_cli` were run over SSH after fresh scoped discovery, comparison with
the retained HTTPS certificate, and strict checking against the previously
observed SSH host key. This was a mistake: the earlier **IPC diagnostic-client
constraint** above explicitly says not to run that client on the physical
camera because its IPC lifecycle may call `unlink`. Although the isolated
synthetic client trial had not shown an unlink on its observed path, it did
not prove the physical invocation's lifecycle. Device-side deletion was not
traced or blocked; whether either invocation attempted or performed a deletion
is unknown. The local SSH processes were traced with deletion denied and
recorded no deletion attempts; that does not cover the camera. No camera
settings write was requested, but no claim that the device filesystem or all
device state was unchanged follows. SSH can also produce audit or log entries.

Both commands returned exit 0 and a JSON object of 10,202 bytes. Their contents
were processed in memory and neither printed nor retained. The second
observation reported four `avSerializer` fields, four each of `width`, `height`
and `fps`, and one `channels` field, among the predefined structural names
checked. The client's JSON output was not the expected raw response envelope;
therefore these results do not establish the actual streamer's response
correlation, independently authenticated device identity, the meaning of any
field, a current video stream, or settlement of either earlier effect. The
SSH host key remains trust on first observation.

The two executed local probe scripts are retained on `trj` as
`/data/tmp/fss-unifi-streamer-read-probe-20261116-01.py` and `-02.py`, with
SHA-256 values `7e28582fccd49ef05d95d42dc920d37d4c415836c306c7796b6d2f87bd4f9b9a`
and `6e642ba6a5c6d4eaa1468522d13c40b7603ac43d599d103f818be8176d990894`.
Their host traces are under `/data/tmp/fss-unifi-streamer-read-20261116-01`
and `-02`. The workspace audit copy has been disabled against execution.
There must be no further physical client invocation unless a device-side
transport/lifecycle is established that cannot delete camera files. The
physical effect fence remains in place. The fallback recorder was active with
eight cumulative restarts and six files modified in five minutes after both
invocations; this observation does not prove gap-free recording.

### Diagnostic output wrapper and queue flag experiment (2026-11-16 UTC)

To investigate the preceding unexpected JSON shape, the copied firmware IPC
client was run only in the existing isolated QEMU chroot with separate network
and IPC namespaces and a synthetic Unix server. For one synthetically
correlated response, client stdout contained a top-level `request` object and
a top-level `response` object; the latter contained the sent synthetic
response fields. This demonstrates the client's wrapper for that test and
provides a plausible explanation for why the prior physical CLI output did not
have `functionName` at the top level. Since those physical output contents
were not retained, this does not establish their nesting or correlation.

The isolated synthetic request without a queue option contained
`queueIfDestUnavailable: true`. The client help describes `-q` with a
different stated default, so its help alone is not evidence of the sent
value. In two additional isolated runs using the same synthetic server,
explicit `-q=1` sent a complete request with that field true and received the
synthetic response, while explicit `-q=0` timed out before the server received
a complete framed handshake. This is a lab result for the simulated endpoint,
not a general statement about camera endpoint registration or the vendor
client's behavior against the physical streamer. The earlier physical
invocations omitted `-q`; their actual queue flag and any queued work were not
recorded. They remain part of the rule violation documented above. The Rust
diagnostic request explicitly sets the field to false, but the experiment
does not prove that a real camera accepts or responds to that request.

The `observe8.py`, `observe09.py` and `observe10.py` synthetic fixtures on
`trj` have SHA-256 values
`1dc03e2810cae720aa97c7eee4b72788b1c630ba08d789a306dde9d1824b95d7`,
`92a6bace7bc19e7114f3353759387232835c16700fad13894bc3ed2b3893b18d`, and
`c72c0ebcd162b3532b1ab5fa5a06442a86f05ba9ee237547d5bf65ce0353bf24`.
Their traces and `help2.trace` are in the same private chroot directory;
deletion syscalls were denied and none were recorded. No physical-camera
request was made for these lab cases. The fallback recorder remained active
with eight cumulative restarts and six recent files. This does not resolve
the physical effect fence, native video capture or retention qualification.

### Admitted same-host diagnostic transport (2026-11-16 UTC)

The experimental Rust diagnostic owner can now be created through an
Asupersync Unix-stream connector. The caller must admit the exact local socket
path, camera claim and generation as well as the existing camera-status and
task authorities. The connector checks admission before and after connecting;
the wrapped transport checks path admission on every read, write, flush and
shutdown poll. The existing bounded, single-use diagnostic exchange and byte
meter remain in force. Socket paths and peer claims are not independent device
authentication, and pathname checks do not eliminate replacement races.

On `ts1`, one real local Unix-socket test with a synthetic peer passed 1/1.
It checked a relative-path refusal, denial before a connection was made, a
successful fragmented-response exchange, and revocation after connecting but
before any request byte was sent. It did not test cancellation during connect
or establish compatibility with an actual camera streamer. Its network
namespace excluded the camera and its deletion-denying trace under
`/data/tmp/fss-ipc-unix-test-20261116-01` recorded no deletion attempts. The
test ran with a 32 MiB stack limit.

The first strict-remote request `j-30110656841646475` did not start due to a
worker disk reservation. The next, `j-30110656841646478`, reached the compiler
but failed on an incorrectly specified lifetime; no tests ran. After fixing the
signature, `j-30110656841646483` built successfully on Linux, but its wrapper
returned 102 after rejecting Linux-to-macOS artifact transfer. The exact test
executable run on the worker had SHA-256
`8f5048c9ed7343e1e009ea15802049967337715d1a654ed866bca86c890b6b85`.
The worker and workspace hashes matched for the connector
`df49d2dd69e8e504435099a2e96870ec110152e707e5a65e071618043a1b6e3e`,
test `efd752c48f9e7ccad8f9ea5e93ae15eb19889f7eda8b72c735ac1c1b38d75fbe`,
and module registry `5c4f8336d27beaf356b6bc88a1cbe06b364027425d7b4b3cbbe9767529bba9d2`.
Rustfmt checks passed. The fallback recorder remained active, with eight
cumulative restarts and six recently modified files.

### Offline streamer dispatch analysis (2026-11-16 UTC)

The previously copied `ubnt_streamer.elf` has SHA-256
`30e9bd2cf236a0f0cfe4c86e458d9fec14a3c41059565f3bdb5450bfbbf12013`.
An offline Thumb disassembly of that exact binary found the
`GetVideoSettings` string in handler registration and a later dispatch
comparison; the matching branch calls the function at `0x26cc8`. Inside that
function, the dynamically linked call sites identified by `llvm-objdump`
include `Encoder::GetCurrentSettings`, a settings transformation, and
`Ipc::SendResponse`. This supports investigating it as an independent
current-streamer settings claim. It does not prove all side effects of the
callee, the shape or truth of a real response, authentication, a historical
effect outcome, or media delivery. In particular it does not justify another
physical client invocation or bypassing the existing fence.

The bounded stdin-only static checker
`experiments/unifi_https_status_lab/streamer_static_xref.py` verifies the
binary hash, two string cross-references, selected registration/dispatch
branch targets, and the two relevant call-site addresses. The PLT symbol
names were inspected separately with `llvm-objdump`, rather than inferred from
the checker's hard-coded labels alone. The workspace and worker checker hashes
matched `261b4045df8f315e7fdbc5c6636017e513af1b30dd171e0ce1de2d86424933bc`;
the network-isolated, deletion-denying trace at
`/data/tmp/fss-streamer-xref-20261116-02/xref.trace` recorded no deletion
attempts. No camera request or device-side code was executed.

The copied streamer cannot yet be run in the existing QEMU laboratory: a
static dependency inventory found 13 absent shared libraries, including
encoder hardware and audio dependencies. Supplying those libraries would not
by itself establish that its hardware-dependent initialization can run in
the chroot. The fallback recorder remained active with eight cumulative
restarts and six recently modified files.

This connector reaches only sockets on its own host. The camera's SSH server
previously refused Unix-socket forwarding, and no remote bridge or device-side
agent is supplied or authorized by this result. It cannot settle the earlier
physical effects, start video, or replace Scrypted and Docker. No physical
camera request was made in this test.

### Pending Rust-to-firmware-listener laboratory check (2026-11-16 UTC)

An explicitly ignored Unix diagnostic test and a separate laboratory fixture
have been prepared to connect the Rust owner to a copied firmware listener in
an isolated chroot. The test expects a deadline because that listener does not
produce a response. The fixture additionally requires the listener to print the
expected synthetic request, ID, sender, and non-queueing flag. Its laboratory
fixture was copied create-only to
`/data/tmp/fss-ipc-rust-fw-20261116-01/fixture.py` on `trj`; its workspace and
remote SHA-256 values match
`d63bd6c8b33e421c064ddf5c0262352ef5ee5500adfe5c68bcce37629a90996f`.
The updated test SHA-256 is
`6f14b682013b77164fae3c1e15254cbde1d7defa5a036ddd3800af5a2641db8c`.

Strict-remote compilation is queued as `9253482693696421915` on the `ts1`
lane; at the time of this note it had not produced a build or test result.
The local command session handle was `76473`. The fixture has not run. Recheck
the same live build handle and exact source
hashes before proceeding; do not submit a duplicate merely because queue
observation timed out. The check, if it passes, would prove only synthetic
request interoperability with the copied listener, not a reply from a real
streamer or access to video. The physical camera remains fenced.

### Rust request received by isolated firmware listener (2026-11-16 UTC)

The pending `ts1` queue entry above terminated before admission with exit 103;
no build ran there. A subsequent `trj` request, job
`j-30110656841646492`, was refused before source or execution admission by an
overlapping source owner. Neither owner nor reservation was disturbed. The
next strict-remote request, `j-30110656841646493`, compiled the same test on
`hz4`; its wrapper returned 102 when Linux artifacts were rejected for macOS.
The worker source/test hashes matched the workspace. The test executable was
copied create-only to the private laboratory on `trj` and matched the worker
SHA-256 `72106d761c3b6d8c306bed34ae9c11ef1f4a1fb3dc534dbf2b17dd5c1318491c`.

In a new chroot with separate network and IPC namespaces, the copied firmware
IPC listener accepted a Unix connection made by the actual Rust task-owned
transport. The listener printed the expected synthetic `GetVideoSettings`
function, sender, request ID, and `queueIfDestUnavailable: false`. The Rust
test observed the expected response deadline and retained a spent owner. The
listener was a vendor diagnostic listener, not `ubnt_streamer`, and supplied
no response. One ordinary synthetic Unix-transport regression also passed 1/1
with the same executable. The tests ran with a 32 MiB stack limit.

The laboratory trace at `/data/tmp/fss-ipc-rust-fw-20261116-01/fixture.trace`
recorded two deletion attempts, both denied. The ordinary regression trace is
under `/data/tmp/fss-ipc-unix-test-20261116-02`. These operations contacted no
physical camera. This establishes only request interoperability with the
copied listener; it does not prove a real streamer accepts a non-queued
request, produce an IPC response, connect across SSH, settle earlier effects,
or establish video capture. The fallback recorder remained active with eight
cumulative restarts and six recently modified files.

### Copied streamer laboratory startup and isolation mistake (2026-11-16 UTC)

A pinned, scoped SSH inventory found the 13 missing shared libraries on the
camera. The initial copy attempt returned remote exit 6 at a camera-side hash
command, before any library contents were retained. A subsequent read-only
copy used two bounded reads of each library and compared SHA-256 hashes on
`trj`, then wrote 13 create-only private copies. A second dependency scan
identified three additional missing libraries; those were copied and checked
the same way. A final static scan of the assembled files found no missing
`DT_NEEDED` names. The repeated-read hashes are not independent device
authentication or signed firmware verification. These SSH operations did not
request camera setting changes or execute the camera's diagnostic client;
SSH may have produced camera audit/log entries. Local deletion-denying traces
recorded no deletion attempts and do not cover device-side operations.

The copied streamer and 44 shared libraries were placed in a fresh private
chroot with an empty `/dev` and separate network and IPC namespaces. Its help
command exited 0. A startup with an empty synthetic configuration exited 1
before an IPC socket appeared. A second fresh chroot added only a synthetic
local syslog socket: its startup also exited 1 before an IPC socket, and the
synthetic log reported missing `/etc/board.info` and `/etc/features.conf`,
unavailable `feature_hdr`, and a crash. These are lab-only observations and
do not establish that supplying those files would make startup succeed.

**Isolation mistake:** The full startup log also says `kill related processes`
and reports that operation failed with `Bad file descriptor`. These tests did
not create a PID namespace or trace signal syscalls. Therefore they do not
establish whether any signal was attempted or whether another host process was
affected. Chroot, network isolation and deletion denial were insufficient to
protect host processes. The workspace startup driver was disabled; there must
be no further firmware startup until a fresh isolation design includes verified
PID separation and a signal-syscall guard, alongside the existing boundaries.
The fallback recorder was subsequently active with unchanged eight cumulative
restarts and six files modified within five minutes; this is not proof about
other host processes or gap-free recording.

The inventory script SHA-256 was
`731298cc235d3bc6f926a8a306c48e31c1c3ca48867267c0480816f1b9e39473`.
Executed copy helpers `-01`, `-02`, and `-03` on `trj` had SHA-256 values
`829cd85376f9ac0f02c724128bab5a175e4ee6b61da34b23a8de0a0322c64385`,
`0293cb697bb69a6a1a69016e2e3e8fbff312af7a67bdf0f21390db1aafe8ccef`, and
`9f68f64162f5f3d2d34cb1167e01d245079dff53c59d35ef79f551ef6922ee74`.
The executed startup drivers `-01` and `-02` had SHA-256 values
`e7047ee3f3940bcd5010c420c9280da42e7f8aa320141779c905535ed2568eb1` and
`b27f334f05f0da3345ec92d0c51e98dbf2c35571feac6257f3bb2a21def8104f`;
the disabled workspace version differs. Private lab files and traces remain
under `/data/tmp/fss-unifi-streamer-chroot-20261116-01` and `-02` on `trj`.
This work does not establish a real streamer response, effect reconciliation,
direct Rust video, or a replacement for Scrypted and Docker.

### PID-isolated firmware startup rehearsal (2026-11-16 UTC)

The preceding host-process uncertainty cannot be resolved retrospectively by
a later sandbox. A synthetic preflight was first run with new user, PID,
network, IPC, and mount namespaces and a proc mount for the new PID namespace.
It compared each namespace identity to the host's, checked its tracer and PID
1 ancestry, and attempted only harmless signal-zero self-probes. A
deletion/signal-denying trace rejected six signal mechanisms, a nonexistent
unlink and rename, and a signal-zero self-probe from a forked child. An
independent PID-1 Python supervisor then repeated those checks inside the same
namespace it would use for its child. That rehearsal ran no firmware.

A fresh device-free chroot and a new controlled PID-1 supervisor then repeated
the synthetic preflight in the same namespace immediately before starting the
copied streamer with an empty synthetic configuration. Its traced descendants
were denied the signal, deletion, rename, truncation, cross-process-write and
namespace-changing syscall families listed in the supervisor. The trace
recorded two denied `tgkill` calls targeting the streamer's own PID; it did not
show a host-process signal. The streamer exited before opening its IPC socket,
and its synthetic log again reported missing board/features files and
`feature_hdr`. This was a negative startup result, not a streamer response or
a hardware emulation. No camera was contacted. No matching lab process was
observed after the namespace exited. This result does not prove universal
sandbox correctness and does not erase the prior untraced isolation mistake.

The exact preflight, supervisor and chroot-preparation source hashes matched
their private `trj` copies:
`c57f605a1962880cdbc7ad85c107392c9e7e62ce22b47c7883a6bedcb2d7f633`,
`f212440583e9e053c97806d010d41f284bd1f7b3813c834f0eb5a80a6c056ee4`, and
`14e21271df78e449c1630d2dc6a2cdf4298c554394331b53667b8f4a0f92a462`.
The preflight trace recorded nine injected refusals, and the streamer trace
two. Both are retained under `/data/tmp/fss-firmware-isolation-20261116-05`;
the separate sandbox rehearsal is under `-04`. The fallback recorder remained
active with eight cumulative restarts and six files modified in five minutes.
The physical camera-effect fence and the requirement for a direct Rust
recorder remain unresolved.

### Copied streamer reaches IPC listen; Rust request times out (2026-11-16 UTC)

With a fresh guarded chroot for each trial, the copied streamer was supplied
only synthetic board, feature, system and version files. The board key/value
shape was informed in part by an older, different camera's [public community
example](https://community.ui.com/questions/Which-firmware-is-the-correct-one/4d0a62ac-0a2d-4fe5-ab4a-01c8b183735a);
none of its device identifiers or actual camera configuration were copied.
The intermediate trials in isolation directories `-06` through `-09`
encountered, respectively, a missing `feature_sdmmc` despite that key in the
synthetic JSON, a variant string-cast refusal, a missing synthetic system
configuration, and a missing synthetic version component. In `-11` the
assembled synthetic files allowed the copied streamer to bind and listen on
its Unix socket. This does not demonstrate that its encoder or event loop was
ready, or that any physical camera would behave the same way.

An explicitly ignored Rust test now requires a correlated successful
`GetVideoSettings` response when used against the isolated copied streamer;
the separate listener test still requires its expected timeout. Strict-remote
job `j-30110656841646509` built the test on `hz4`; its wrapper returned 102
after declining Linux-to-macOS artifact transfer. The exact worker executable
was copied create-only to `trj` and matched SHA-256
`be434b11d9af8e18c545598366d41e9e223292e8e87beb45fb736e13443df55c`.
The worker and workspace test hashes matched
`0865a3df4ec4041ffa2252659f40b417d496d0623f26d8e48dc43a019bd853c2`.

In three guarded chroots, the Rust test failed 0/1 each time with a response
deadline. In the third trial the supervisor waited four seconds after observing
the socket before the two-second request; the same failure occurred. Bounded
syscall traces in the latter two show successful client connect and 234-byte
send, and no `accept` or `accept4` call in the traced streamer before shutdown.
Thus these trials do
not establish that the streamer received the request, and they do not prove a
protocol incompatibility. The supervisor forcibly stopped its own tracer
after the bound; the PID namespace exited. The synthetic logs and traces are
under `/data/tmp/fss-firmware-isolation-20261116-12` through `-14`. No camera
was contacted and the earlier host-process and camera-effect uncertainties
remain unresolved.

The same executable passed the ordinary synthetic Unix admission/revocation
test 1/1 and the copied diagnostic-listener fixture 1/1. Both used a 32 MiB
stack and deletion-denying isolated traces; neither is a real-streamer
response. The final supervisor source hash matched its private copy at
`b054d782ebf588ca4c4e83aea001a1f46f29e7cb4d39c0a88cff8e6caf674938`.
The fallback recorder remained active with eight cumulative restarts and six
recently modified files. Direct physical-camera capture, crash recovery,
30-day retention qualification and replacing Scrypted/Docker remain open.


### Laboratory syslog backpressure corrected; startup crash exposed (2026-11-16)

The previous `-14` trace ends inside a syslog `sendto`. Source inspection found
that the laboratory supervisor stopped reading its synthetic datagram log
socket during the four-second initialization wait and synchronous Rust client
wait. This permits logging backpressure to stop firmware initialization before
its IPC accept loop. The old timeout is therefore not evidence of protocol
incompatibility or a sufficient reason to retry a physical request.

Added `lab_log_pump.py`: drain logs during initialization/client waits; bound
retained logs and each client output pipe to 64 KiB; keep consuming overflow
with omission counts; preserve caller ownership on timeout. The supervisor now
checks for firmware exit before launching the client, returns failure when the
client did not succeed, and takes an explicit private fresh-chroot path. No
production Rust code, camera configuration, effect fence or recorder service
was changed.

On Linux `trj`, two synthetic tests passed. The backpressure case first proves
that a no-drain wait times out, then drains the same child to success while
consuming 256 KiB of logs and 128 KiB on each output pipe. It verifies retention
caps and overflow counts. The second verifies deadline expiry retains the child
for owner cleanup. The initial macOS pressure test failed because the child
exited before the expected timeout; that mechanism is now explicitly Linux-only.
macOS passed the timeout test and skipped the Linux case. Syntax and diff checks
passed; these are laboratory-helper checks, not project or release qualification.

Two fresh device-free chroots used the existing user/PID/network/IPC/mount
namespace separation and the same-namespace signal/deletion guard preflight.
The first corrected run (`/data/tmp/fss-log-pump-20261116-01`, chroot `-15`)
drained 17 log messages and observed firmware exit 1 without forced termination.
Its log reports video-input initialization followed by a signal-11 crash. The
Rust client returned `Io(ConnectionRefused)`; it did not obtain a reply. The
then-current supervisor incorrectly returned zero despite that failed client;
the final patch corrects that exit status.

The final supervisor repeated the guarded startup in
`/data/tmp/fss-log-pump-20261116-02`, chroot `-16`. It again retained 17 messages
ending in the signal-11 crash report, detected exit before the client and
returned 1 with `rust_client_exit=not_run`. Its trace has no accept/accept4,
one denied unlink, and no denied signal syscall; the synthetic preflight has
nine injected refusals. This supports the logging-stall diagnosis and exposes
a subsequent initialization failure. It does not establish the exact crash
cause, hardware emulation, real streamer interoperability, or historical
camera-effect settlement. No physical camera was contacted by these trials.

Final workspace/remote helper hashes:
- pump: `1feb9ac30a697f37b13ee8ba3cff9f429e95a19f8ad0bd4c73fe577019ca0563`
- tests: `25a5fe43d542c11652ded08cccfe124e9c9a0a09ddf88a29ad5e10efb0e45d8d`
- supervisor: `3effc2dd7dcb7f301c1ef3a9f50c4e66eafc590f4fce4057d521ef1a4694cb66`
- preparer: `54c295b45fea3069b70dab34fd095d4886e571b969dc5dcffaef98b7beef4d52`
Final run stdout hash: `bdefd0fc7ccd2db85491afb2e8d899a8c6284522aa4c8ceb75ccd7823568c27e`.
Final streamer trace hash: `eb32826036b2a42737b66be78511f6165ffafb166eb6aaefc7fc3ee01e729519`.
The reused Rust test binary was hash-checked against
`be434b11d9af8e18c545598366d41e9e223292e8e87beb45fb736e13443df55c`;
no new Rust build or Rust passing test is claimed here.

The existing recorder was active/running with eight cumulative restarts and six
fallback files modified in five minutes. No matching QEMU streamer process was
observed after the first namespace exited. The separate fleet gate reported
existing duplicate launchd labels and eight plist-doctor findings, with a stale
ARP warning; those other camera lanes were not repaired or re-armed.

Next: inspect the retained synthetic crash dump and copied encoder initialization
statically before another firmware startup. Do not add real hardware devices,
run the physical diagnostic client, replay settings, apply the old whole-track
checkpoint, or release the physical fence on the strength of this result. The
two earlier camera effects, direct full-resolution capture, uninterrupted
recording/recovery and 30-day retention qualification remain open.
