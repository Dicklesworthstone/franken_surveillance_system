# Asupersync 0.6 TLS acceptor experiment

This isolated experiment exercises the released Asupersync 0.6.2 `tls-core`
acceptor and explicit-context I/O with rustls-pure and disposable loopback
credentials. It does not upgrade the FSS runtime or operate a camera. Supply a
short-lived localhost certificate and PKCS#8 key through `FSS_LAB_CERT_DER` and
`FSS_LAB_KEY_DER`; never use camera credentials as fixtures.

Both endpoints use the same provider, so a pass is not independent
interoperability or a provider audit. The provider still accesses ambient OS
entropy; FSS admission and explicit entropy authority remain unresolved.

On 2026-11-05, the isolated test binary built remotely and passed one loopback
exchange on `trj` with a disposable certificate (SHA-256 of binary:
`ec200efd45e713868d9bf207194689ce39dcdee3ddc3750b5056d3ac9fc2f3f2`).
The Linux normal dependency tree included `getrandom` but no `ring` or
`aws-lc-rs`. It exercised Asupersync's `accept_with_cx`, context-aware
read/write/flush, and TLS 1.3; it did not use the FSS 0.5 task authority,
network metering, the camera, or an independent TLS implementation.

An additional disposable-fixture test on 2026-11-05 used OpenSSL 3.5.5 as an
independent TLS 1.3 client. The client verified the correct fixture CA and
hostname and exchanged fixed payloads with the Asupersync/rustls-pure server;
using a different CA caused the client to reject the server. All three tests
(the original same-provider fixture and the two OpenSSL cases) passed on
`trj`. Binary SHA-256:
`1f072da45997bf9ee0f0cba4182bcad65309935f3c3af2942d1eff096ecf1c85`.
These tests do not authenticate a client or a real camera, audit the provider,
exercise FSS task authority, or establish dependency admission.

A further native-loopback test waited until `accept_with_cx` actually returned
`Pending` with a silent TCP peer, requested cancellation on its runtime context,
and observed `Interrupted` plus EOF at the peer. All four ignored fixture tests
passed together on `trj`; the test binary SHA-256 was
`76232b155b8cde120fcc3e921ccbed20ff3e0f1088ece8a488fa434177c1550a`.
This is a single cancellation boundary, not a complete supervisor or fault
campaign; it does not exercise FSS task ownership or a camera.
After source formatting, all four fixture tests passed again on `trj`; the
formatted-source test binary SHA-256 was
`d0fd9ed46c0e9e253bd26a17ab65be163b27aa9573e60aa655a1eb6914304b33`.

## Owned-session composition fixture

`fss_owned_tls_session.rs` is an integration test for an **isolated upgraded
copy** of the FSS workspace, not a target of this standalone lab. The copy
pins Asupersync 0.6.2 in `fss-runtime`, `fss-reference`, and `fss-cli`, enables
`tls-core` for `fss-reference`, and adds dev dependencies
`rustls = { version = "=0.23.46", default-features = false, features = ["std"] }`
and `rustls-pure = "=0.15.4"`. Place the fixture under
`crates/fss-reference/tests/unifi_owned_tls_lab.rs` in that copy, resolve its
lockfile, and run it with the disposable certificate variables above. Do not
point it at a real camera.

The first independently anchored nested-meter test failed with an authority
refusal; a later run failed intermittently on iteration 111 of a repeat test.
The corrected fixture uses the shared, task-bound `MeteredClock` in the main
source. On `trj`, its binary SHA-256
`aed252c4d81832204d5d429dc938c1edc87c56965905b4f08131514cce51be68`
passed 250 consecutive fixture runs, each completing an owned task receipt,
TLS handshake, WebSocket upgrade and UniFi hello observation. Both peers use
the same experimental provider and the MAC remains an unauthenticated claim.
The result is not a full fault campaign, independent peer proof, a camera
session, or a production dependency admission.

`fss_owned_tls_upgrade_owner.rs` is a second fixture for the same isolated
upgraded workspace. It uses `unifi_direct::owner::accept` instead of manually
reading and writing the HTTP upgrade. On 2026-11-05, it passed once on `trj`
with disposable same-provider TLS credentials; the test binary SHA-256 was
`a7c65c4f0b649dbb6c95859db7a399553a7024bd17a2fa343211c55bcd91c9e6`.
Its source SHA-256 was
`61af95c21150648ca1d3750a82aa0deeabdd05477891eba77fdcbc374f615f78`.
The admission callback accepts a fixture MAC claim only; it does not establish
real device identity or authorize camera control. The original
`fss_owned_tls_session.rs` fixture and its earlier repeat evidence remain
separate.
