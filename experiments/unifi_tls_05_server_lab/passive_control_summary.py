#!/usr/bin/env python3
"""Summarize bounded decrypted WebSocket frames in a running controller.

This lab-only observer intentionally outputs no payloads, addresses, message
identifiers, or unrecognized function names. TLS reads are not attributed to
an individual socket, and an incomplete or coalesced read is not a message.
"""
import collections
import json
import os
import struct
import subprocess
import sys
import time

NAMES = {
    "ubnt_avclient_timeSync": "time_sync",
    "ubnt_avclient_hello": "hello",
    "ubnt_avclient_setParameter": "set_parameter",
    "ubnt_avclient_paramAgreement": "param_agreement",
    "ChangeVideoSettings": "video_settings",
    "EventSmartAudio": "smart_audio",
}


def classify(raw):
    if len(raw) < 2 or raw[0] != 0x82:
        return "non_binary_or_fragment"
    length = raw[1] & 127
    offset = 2
    if length == 126:
        if len(raw) < 4:
            return "incomplete"
        length = struct.unpack_from(">H", raw, 2)[0]
        offset = 4
    elif length == 127:
        if len(raw) < 10:
            return "incomplete"
        length = struct.unpack_from(">Q", raw, 2)[0]
        offset = 10
    masked = bool(raw[1] & 128)
    mask = raw[offset:offset + 4] if masked else b""
    offset += 4 if masked else 0
    if len(raw) != offset + length or (masked and len(mask) != 4):
        return "incomplete_or_coalesced"
    payload = raw[offset:]
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    try:
        message = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return "non_json"
    if not isinstance(message, dict):
        return "non_object"
    if (message.get("from"), message.get("to")) not in (
        ("UniFiVideo", "ubnt_avclient"), ("ubnt_avclient", "UniFiVideo")
    ):
        return "other_envelope"
    function = message.get("functionName")
    name = NAMES.get(function, "other") if isinstance(function, str) else "other"
    correlation = message.get("inResponseTo")
    correlated = "correlated" if type(correlation) is int and correlation != 0 else "uncorrelated_or_unknown"
    requested = "reply_requested" if message.get("responseExpected") is True else "reply_not_requested_or_unknown"
    return f"{name}:{correlated}:{requested}"


def main():
    if len(sys.argv) not in (2, 3) or not sys.argv[1].isdigit() or int(sys.argv[1]) < 2:
        raise SystemExit("expected controller PID and optional 1..300 second duration")
    pid = int(sys.argv[1])
    if len(sys.argv) == 3 and (not sys.argv[2].isdigit() or not 1 <= int(sys.argv[2]) <= 300):
        raise SystemExit("invalid observation duration")
    duration = int(sys.argv[2]) if len(sys.argv) == 3 else 30
    if os.readlink(f"/proc/{pid}/exe") != "/usr/bin/node":
        raise SystemExit("controller process is not the expected node binary")
    program = r'''config = { max_strlen = 256; }
uprobe:/proc/PID/root/usr/bin/node:SSL_read /pid == PID/ { @r[tid] = arg1; }
uretprobe:/proc/PID/root/usr/bin/node:SSL_read /pid == PID && @r[tid]/ {
  $p=@r[tid]; $n=retval;
  if ($n >= 6 && $n <= 4096 && (*(uint8*)uptr($p) & 15)==2) {
    @seq[tid]++; $s=@seq[tid];
    for ($i : 0..18) { $o=$i*240; if ($o<$n) { $z=$n-$o; if ($z>240) {$z=240;} printf("R %d %d %d %d |%rh\n",tid,$s,$n,$i,buf(uptr($p+$o),$z)); } }
  } delete(@r[tid]);
}
uprobe:/proc/PID/root/usr/bin/node:SSL_write /pid == PID/ {
  $p=arg1; $n=arg2;
  if ($n >= 6 && $n <= 4096 && (*(uint8*)uptr($p) & 15)==2) {
    @seq[tid]++; $s=@seq[tid];
    for ($i : 0..18) { $o=$i*240; if ($o<$n) { $z=$n-$o; if ($z>240) {$z=240;} printf("W %d %d %d %d |%rh\n",tid,$s,$n,$i,buf(uptr($p+$o),$z)); } }
  }
}
interval:s:DURATION { clear(@r); clear(@seq); exit(); }'''.replace("PID", str(pid)).replace("DURATION", str(duration))
    trace = subprocess.Popen(["sudo", "-n", "timeout", f"{duration + 30}s", "bpftrace", "-e", program],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    counts = collections.Counter()
    pending = {}
    sequence = []
    started = time.monotonic()
    assert trace.stdout is not None
    for line in trace.stdout:
        try:
            label, data = line.rstrip().split("|", 1)
            direction, tid, sequence, total, index = label.split()
            total, index = int(total), int(index)
            chunk = bytes.fromhex(data)
            if direction not in ("R", "W") or not (6 <= total <= 4096 and 0 <= index < 18 and len(chunk) <= 240):
                continue
            key = (direction, tid, sequence)
            if len(pending) >= 32 and key not in pending:
                counts["capacity_refusal"] += 1
                continue
            entry = pending.setdefault(key, {"total": total, "chunks": {}})
            if entry["total"] != total or index in entry["chunks"]:
                counts["chunk_conflict"] += 1
                pending.pop(key, None)
                continue
            entry["chunks"][index] = chunk
            needed = (total + 239) // 240
            if len(entry["chunks"]) == needed:
                raw = b"".join(entry["chunks"].get(i, b"") for i in range(needed))
                pending.pop(key, None)
                if len(raw) == total:
                    label = f"{direction}:{classify(raw)}"
                    counts[label] += 1
                    if (len(sequence) < 64 and
                            (label.split(":")[1] in ("time_sync", "hello", "param_agreement", "set_parameter", "video_settings")
                             or (label.startswith("R:other:") and label.endswith(":reply_requested")))):
                        sequence.append((int((time.monotonic() - started) * 1000), label))
                else:
                    counts["incomplete_chunks"] += 1
        except (ValueError, TypeError, struct.error):
            continue
    status = trace.wait()
    print("trace_exit", status, "incomplete_groups", len(pending))
    for key in sorted(counts):
        print(key, counts[key])
    for elapsed_ms, label in sequence:
        print("startup_candidate", elapsed_ms, label)
    return 0 if status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
