# Explicit RTSP keepalive methods

Reference implementation increment, 2026-10-15. This adds an owner-selected liveness
method to the native AVC and HEVC capture paths. It is not a camera support claim.

## Operator use

Add this option to the ordinary `fss-capture-rtsp` command or its `reconnect` subcommand:

```text
--keepalive-method get-parameter
```

Preview the complete command without `--approve`, then repeat it with the returned
approval. Changing the method invalidates an earlier capture/supervision/reconnect
approval before destination creation or camera connection. Every possible reconnect
attempt carries the chosen method in its own approved child plan. Recovery previews
must repeat the original options, including this one, to preserve original child approvals.

Omitting the flag or using `--keepalive-method options` selects the existing OPTIONS
keepalive. The default emits exactly the prior canonical approval bytes. Selecting
GET_PARAMETER adds a control-policy domain to the approval, not to the media clock:
receive/decode clocks, namespace, timing evidence, codec configuration and recording
format do not change merely because the liveness method changes.

The preview and `started` JSONL detail expose `keepalive_method` (`OPTIONS` or
`GET_PARAMETER`) and `keepalive_fallback: false`. Each `request_queued` detail retains
the existing semantic `command` label (`KEEPALIVE`) and adds the actual `method`.
A queue report still means local preparation, not dispatch, server acceptance,
recorded pictures, continuity or durable publication.

## Wire and authentication contract

The selected GET_PARAMETER operation contains no parameter names and no body. It
uses the already-negotiated aggregate URI, current Session, fresh CSeq and an explicit
`Content-Length: 0`. It neither reads nor changes camera settings. RFC 2326 section
10.8 describes the empty-entity form as a liveness test:
https://www.rfc-editor.org/rfc/rfc2326.html#section-10.8

The shared session owns the method and target used by both unsigned wire preparation
and Digest A2. Digest's bounded method validator now admits uppercase underscores,
while continuing to refuse controls, spaces, non-ASCII and overlong methods. The native
SHA-256, SHA-256-sess and explicitly permitted legacy algorithms retain their existing
realm, nonce, qop, retry, counter and downgrade checks. Passwords, challenge text and
Authorization values are not added to reports or recording objects.

A 401 retry preserves the original selected command, URI, send-time basis and absolute
response deadline, while reserving a fresh CSeq. Informational or unrelated responses
cannot renew the request. A successful liveness response renews the conservative
session lifetime from the request issue time, not from the delayed reply time.
Missing replies, changed Session, 405/501 or other rejected responses do not switch
methods. Existing failure/retirement handling preserves remote-session uncertainty.

## Library surface

`ClientCommand::KeepAlive` remains OPTIONS. The new explicit command is
`ClientCommand::KeepAliveGetParameter`. `wire_method()` is the shared method mapping;
`is_keepalive()` distinguishes liveness commands from media transitions. Manual native
AVC/HEVC owners forward this command through their existing scoped transport APIs.
Exhaustive downstream matches over `ClientCommand` must account for the added variant.

The selected-configuration HEVC archive additionally exposes `select_keepalive` and
`keepalive_command`. Selection must precede its first prepared RTSP request; invalid
or late selection is non-consuming and performs no I/O. It cannot rewrite a pending
Digest challenge or partly sent request. The capture CLI sets this choice before its
first poll. The existing independent-configuration automatic HEVC recording wrapper
and standalone automatic AVC wrappers retain their OPTIONS default; they are not
silently reconfigured by the CLI option.

Source collection, timing, source-first/root-last publication, independent checkpoint
pins, privacy, finite work limits and reconnect refusal rules are unchanged. GET_PARAMETER
does not encrypt the transport or establish server identity. Real camera compatibility,
TLS and field continuity qualification remain separate work.

## Reproducible checks and current evidence

```sh
bash scripts/bootstrap_toolchain.sh
bash scripts/qualify_rtsp_keepalive.sh
```

The script executes the existing authentication group, eight new sans-I/O session
contracts, existing payload-selection/HEVC archive regressions, capture unit tests,
five new native process contracts and existing reconnect process tests. It continues
independent groups after a failure but returns failure if any group fails. CI calls
the same script; `scripts/qualify.sh` and retained DSR receipts remain release authority.

The authentication increment adds three unit tests, including six independent
hashlib golden vectors spanning SHA-256/SHA-256-sess and explicit legacy qop/no-qop.
Those golden computations were executed independently during development. Rust tests
have NOT been executed in the editing environment: Cargo/rustc are unavailable and
GitHub DNS prevents a local checkout. Source diffs were reviewed, and the supplementary
native runner was queued at the last observation. Neither committed tests nor a queued
workflow is passing evidence. Formatting, complete manifest reconciliation and release
qualification are not asserted by this increment.

Process fixtures bind loopback only. They cover pure default/explicit approvals,
reconnect child selection, stale/invalid method refusal before I/O, exact empty request
bytes, successful AVC/HEVC recording and catalog publication after liveness, and missing,
wrong-session or rejected replies without fallback or fabricated recording success.
They do not constitute real-camera testing or an authenticated live-camera support tuple.
