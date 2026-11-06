# Isolated UniFi TLS 1.3 provider laboratory

This credential-free experiment compares the separately released `rustls-pure`
0.15.4 provider against the owner's G4 using task-owned, metered Asupersync TCP.
It sends no HTTP, WebSocket messages, credentials, or camera settings. Its
same-network observed certificate is not independent proof of camera identity.
A successful handshake is interoperability evidence, not production security,
authority, or dependency admission. The provider's authors report no outside
audit; its published source also calls OS randomness independently of FSS task
authority. It supports TLS 1.3 only. See `DEP-TLS-001` for the open gate.

The source and lockfile are isolated from the main workspace. The opt-in ignored
test accepts the owner-scoped certificate path, private IP, case, and scope
digest through environment variables. `match`, `mismatch`, and `bad-key` cases
check the exact observed pin and a different valid P-256 signature key.

On 2026-11-05, the three opt-in cases ran against the owner's G4 from `trj`.
The matching observed certificate completed TLS 1.3 with ChaCha20-Poly1305;
the deliberately changed certificate and different valid P-256 key were
rejected. All three returned completed task receipts, and no application data
was sent. The recorder and discovery timer were active afterward. This is a
client-side handshake only: the camera-to-controller server role, trusted camera
identity, operating system entropy boundary, security audit and production use
remain unqualified. The explicitly locked Linux normal dependency tree did not
contain `ring` or `aws-lc-rs`; it did include `getrandom`.

The debug-stripped test executable SHA-256 was
`7a45e7be08b877c99390d987234d883e2845b79b57f5a2b4c55903ffab482835`.
It was built on `hz3` at base `955562d03290395612e2bd59eaa8066de79ddd72`,
clean overlay `1787cc58c5ac72c7af299401b8ffee2ecf0bacd94e5cc4fd13ff6d44b86f0358`.

A separate synthetic loopback test exercised the server role with a disposable
P-256 certificate, the same provider on the client side, and task-owned
metered Asupersync TCP on the server. Both directions transferred fixed fixture
bytes and the task receipt completed. This is same-provider loopback evidence,
not independent interoperability or a camera-to-controller session. The
updated debug-stripped test executable SHA-256 was
`e9bdc34b6351755b1765239ee7ef7171537166cabaafc274be0bdcf1e605d398`,
built with clean overlay
`2c3ca15d830de39a4d2a356972a6e58cf69d2ac4d53cba8196452800cbe0dddd`.
