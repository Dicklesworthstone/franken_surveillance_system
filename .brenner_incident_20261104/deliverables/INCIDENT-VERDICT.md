# INCIDENT VERDICT — RS-20261104-cameraroot

## Verdict (one line each)

**M1 — C660 "shell binds but carries no commands": ROOT-CAUSED.**
The C660's busybox has **no `nc` applet at all** (applet table: telnetd/tftp/wget only). The default
ROP command `/bin/busybox nc -lk -p 4444 -e /bin/sh` **can never work** on this camera — every prior
fire bound nothing or bound a dead socket. The telnetd applet IS present; the already-deployed
`telnetd -l /bin/sh -p 4444` command is the correct payload. H-001 confirmed (EV-T-001, rootfs
extraction `/tmp/c660_rootfs`). Residual: telnetd needs devpts; /dev/pts exists in rootfs.

**M2 — C460 "root proven 3× but never converted": DEPENDENCY-CHAINED, not neglected.**
Conversion = pull `/proc/mtd` + `/bin/main` from a live shell → derive the unit's own gadgets →
install repeatable ROP. Deriving gadgets from *firmware* is blocked on the vendor sstarXZ decoder
(EV-T-002: 4-block VLQ table parsed; custom decoder desyncs; liblzma rejects all probed starts).
The doc-prescribed path — pull the binary from a live shell — requires the very shell that only
exists during a wake window. So: conversion is wake-gated, and tonight's deep-night dormancy is the
whole story. Not a defect in the chain; the chain fires on next motion.

**M3 — Wyze "polls but never fetches": ROOT-CAUSED and FIXED.**
The camera's own request body (captured verbatim) asks for `filename=launch.sh,
version=14.9.50040.r` — the process channel is a real, wanted path. Our historical responses handed
back presigned URLs with `X-Amz-Signature=000...0` (forged), which the SDK can reject pre-fetch —
matching 10 polls → 0 fetches. Fix deployed and proven: `get_download_location` now passes through
to the real cloud (Host-header routed); replaying the camera's exact body returns a **valid SigV4
URL** (`sinker-t-usw2.s3.us-west-2.amazonaws.com/...launch.sh?X-Amz-Signature=3b69821f...`).
DNS spoof suffix-matches that host; the forge cert SAN explicitly includes it; the forge serves
that exact path (200/661B); the camera already pulled our CA bundle 59× (it trusts our PKI).
Every layer between poll and payload-fetch is now verified. H-003 confirmed-mechanism,
fix deployed. H-004b (component-checksum manifest gate) remains the one open risk; our response's
launch.sh checksum is the md5 of the bytes we serve, which is the correct-by-construction case.

## What was true vs false in the "big game"

TRUE: exploit fires, shells spawned (3×), MITM carries camera traffic, payloads staged and served.
FALSE (now corrected): "shell grabbed" — we never read a byte from a shell until tonight's guard
fix; the nc -z probe consumed every one-shot shell; the C660 default command was impossible on that
camera's busybox; the Wyze fetch gap was OUR schema defect, not camera sleep.

## Next actions (each owned, each observable)

1. **C660**: next PIR wake → c660-sweep fires ROP with `telnetd -l /bin/sh -p 4444` → expect
   `FOUND — telnetd up` + recon_telnetd.txt with `uid=0`. If 4444 stays closed, H-002
   (gadget drift) escalates and the discriminating test is a pulled /bin/main diff.
2. **C460**: next PIR wake → guard fires; on `SHELL on` the postshell chain runs automatically →
   `/tmp/pane1/192.168.4.33/recon_auto.txt` with `uid=0` + /proc/mtd → gadget derivation unblocks.
3. **Wyze**: next poll cycle (minutes–hours) → expect camera-sourced `GET /wyzeedgeai_cam_v4_test_protocol/14.9.50040.r/launch.sh`
   in forge log, then `/fss-ran` beacon on :8080 if the process manager executes it. If polls
   continue with still-zero fetches after real-URL responses, H-004b (checksum gate) escalates:
   mirror the real component bytes or serve a manifest whose checksums match our served bytes.
4. **Operator gates** (unchanged): Owlet power-cycle; Yi AP toggle (yi-runbook.md).

## Metrics

- Hypotheses: 4 filed, 4 adjudicated (2 confirmed, 1 partially confirmed, 1 downgraded-unresolved), 3rd-alternative included
- Falsifiers: 4/4 non-empty; discriminating tests executed where reachable tonight (rootfs inspection, live replay)
- Camera-side observables now instrumented: forge log request+response logging, beacon endpoint, sweep FOUND lines
