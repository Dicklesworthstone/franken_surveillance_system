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
