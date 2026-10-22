# Wyze / TUTK lab method (owner devices)

Practical notes from cracking one owner-authorized Wyze Cam v4 (HL_CAM4, firmware 4.52.17.26) over
the LAN without disassembly, SD card or vendor developer program. Nothing here is release-qualified.
No secrets: the ENR is per-device and lives in the owner's lab config, never in this file.

## 1. Why the wire matters more than the payload

`iCamera` dispatches on the **first `u16`** of the decrypted DTLS application data. Getting the head
wrong sends your bytes to a handler that will happily ignore them, and you will conclude "the
payload is wrong" when the frame never arrived. Two rules, both learned the hard way:

| Message class | Head |
|---|---|
| Vendor IOCTRL | `"HL" | version **0x25** | 0x00 | cmd u16 | len u16 | 8 zero | payload` |
| K-command (auth/stream, 1000x) | same but version **5** |
| AV frame | byte0 = channel (`0x07` I, `0x05` P, `0x03` audio), byte1 = frame type (`0x01`), `u16` pkt_total @12, `u16` **declared payload size** @16, raw — **no HL head** |

`0x25` vs `5` is not cosmetic: with 5 the camera only answers after a DTLS retransmit, with `0x25`
it answers on the first send. `fss-tutk` encodes this as `build_ioctl_hl` vs `build_hl`.

The acknowledgement for `0x284C` is `0x284D` with a single byte. That byte is a generic result code
(constant `02` for every payload tried, including known-accepted ones) — do not read it as a
length verdict.

## 2. Where the bugs actually are

Two independent classes were tested:

- **K10000 `audioEncoderList` (CVE-2023-6322)** — dead on this build. The loop is
  `min(array_size, 10)` (`0x467e84`), the destination is a 10-int array, and the whole payload is
  guarded to 1..900 bytes (`0x4680cc sltiu len-1,0x384`). The published v3 ROP chain cannot be
  reused; 11..900-entry arrays change nothing.
- **The AV data path (CVE-2026-38698)** — live. `tutk_packet_Alloc` allocates `0x28 + len` and
  `memcpy`s `len` from the *received* buffer with no check that `len` matches the datagram. Declare
  more than you send and the camera reads past the payload into adjacent heap. `0xFFFF` over a
  1264-byte frame kills `iCamera` and the camera reboots in ~8 s. This is an over-read that lands in
  a correctly-sized allocation, so the win condition is a **heap spray** whose bytes end up being
  interpreted as structure, not a straight `memcpy` overflow. The 1280-byte `auStack_538` buffer in
  `FUN_0067a0d4` is *not* overflowed: every path that reaches it carries ≤0x3ff bytes.

The published Pan-v3 PoC's tail markers (`0x0095d020`, `0x0000000e`, `0x000000ff`) are Pan-v3 heap
addresses. They are placeholders on a v4.

## 3. Generic config write (useful beyond the exploit)

`0x2780` is not in the ioctl table but is accepted: a generic `paracfg` setter taking the item id in
the first payload byte, answering `0x2781` with the applied value. Setting item 11 flips
`settingParm.telnet` from `2` to `1` and survives a reboot. The id→function table is an 8-byte-stride
`bsearch` array (`0x8d5c98`, 157 entries, apply fn at +4), so any entry is reachable the same way.
`0x2781` itself is unhandled and only echoes `0x0001`.

## 4. No shell on this firmware — plan accordingly

The v4 system rootfs contains **no `/bin/sh`, no busybox, no `telnetd`**; only `iCamera`, `dmon`,
`dnsmasq`, `iotclient`, `wpa_supplicant` and fsck helpers. Consequences:

- `system("telnetd &")` cannot succeed, which is why the paracfg telnet flag produces no listener.
- ROP must call **`exec_shell_sync`** (`0x8be960`; loads the target from `0x8d4bb0`, needs no `$gp`,
  command pointer in `$a0`), not `system()`.
- Anything you want on the device afterwards must be uploaded; assume no shell to wget with.

## 5. Recovery and safety

- The camera recovers from an `iCamera` crash on its own in ~5-10 s (init respawns it); a reboot is
  the worst observed outcome. Nothing here has required a reflash.
- One camera per agent. Discovery takes ~100-500 ms normally and fails outright when two agents
  race the same unit — back off and use another device rather than retrying.
- Keep the vendor `recovery_*_<version>.bin.zip` for the running version on hand; it is the SD
  recovery fallback if a future write path bricks something.

## 6. Harness

`crates/fss-tutk/examples/session_probe.rs` drives discovery → DTLS → AV login → K-auth → stream
against a real unit and can send `--ioctl`/`--payload-file` (version-correct) or `--raw-file`
(repeatable, for AV frames). `SessionEvent::Ioctl` hexdumps camera→client IOCTRLs. `fss-capture-tutk`
carries the same knobs for operator use. Build the example with `rustc --crate-type lib` +
`--extern`, not cargo: the cargo shim refuses local fallback for a darwin target.

## 7. Re-measured: the over-read is real, the crash is garbage-dependent

Follow-up trials (clean session teardown added to the probe — an abrupt stop leaves the camera's
session half-open and the *next* probe stalls in DTLS, which silently invalidated several early
runs) give a sharper picture than "0xFFFF always crashes":

| Declared `len` over a 1264-byte frame | Attempts that actually sent | Crashes |
|---|---|---|
| `0x800` / `0x2000` / `0x8000` / `0xFFFF` | mixed | 4 across the whole campaign, none reproducible back-to-back |
| `0xFFFF` with a 32-byte payload | 1 | 0 |

Mechanism: the declared length makes the parser slice the frame into `ceil(len/0x400)` packets and
`tutk_packet_Alloc` allocates `0x28+len` each, so there is **no heap write overflow** — the pages
are correctly sized. What is wrong is the *content*: everything past the delivered bytes is adjacent
heap, so the camera ends up with a large frame of mostly-garbage. Whether that faults depends on
what the garbage happens to be (decoder/muxer parsing), which is why the crash rate varies by unit
and by heap state.

Consequence for exploitation: treat it as a **length-trust / over-read** primitive, not a classic
copy overflow. Either (a) the spray must make the adjacent heap parse as a plausible H.264 frame
that reaches a fault, or (b) find a consumer that copies `len` bytes into a fixed buffer downstream
of the packet. Do not plan a ROP chain from a saved return address until (a) or (b) is identified.

The clean teardown is now part of the probe (`sess.close()` + 200 ms drain). Always let the probe
exit normally; a `kill` leaves the session wedged for the next attempt.
