#!/usr/bin/env python3
"""Capture the Owlet app's auth wire path with a frida script, without a TTY.

The frida CLI exits as soon as stdin closes, so a headless capture needs the bindings: this keeps
the session open for --seconds, streams every console.log line to --out with a wall-clock stamp,
and prints a per-address summary at the end.

  owlet_auth_capture.py --out /tmp/owlet_cap/java_hook.log --seconds 120
  owlet_auth_capture.py --spawn com.owletcare.sleep --out ...   # cold start (login state persists)

The hook script is owlet_java_socket_hook.js next to this file.
"""
import argparse
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="emulator-5554")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--spawn", help="package to cold-start instead of attaching")
    ap.add_argument("--script", default=os.path.join(HERE, "owlet_java_socket_hook.js"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=float, default=120.0)
    a = ap.parse_args()
    if not a.pid and not a.spawn:
        ap.error("need --pid or --spawn")

    dev = frida.get_device(a.device, timeout=10)
    pid = a.pid
    if a.spawn:
        pid = dev.spawn([a.spawn])
    session = dev.attach(pid)
    if a.spawn:
        dev.resume(pid)
        time.sleep(2.0)   # ART is not ready the instant the process is resumed (Java.use -> 0x0)
    src = open(a.script).read()
    # frida 17 does not expose `Java` to create_script (the CLI injects its bundled bridge and
    # posts it back on demand); prepend the same bundle so a headless run has the same globals
    bridge = os.path.join(os.path.dirname(frida.__file__), "..", "frida_tools", "bridges", "java.js")
    prelude = ""
    if os.path.exists(bridge) and "Java." in src:
        prelude = open(bridge).read() + "\nvar Java = bridge;\n"
    time.sleep(1.5)   # let the bridge's runtime settle before evaluating (Java.use -> 0x0)
    script = session.create_script(prelude + src, runtime="v8")
    t0 = time.time()
    def on_message(msg, data):
        # append per message: frida delivers on its own thread and a held fd proved unreliable
        line = f"{time.time() - t0:8.3f}s {msg.get('payload', msg)}\n"
        with open(a.out, "a") as fh:
            fh.write(line)
        print(line, end="", flush=True)

    script.on("message", on_message)
    script.load()
    print(f"attached pid={pid} script={a.script} seconds={a.seconds}", flush=True)
    try:
        time.sleep(a.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
