#!/usr/bin/env python3
"""Receive the per-partition backup streams upgraderun.sh sends before it writes anything.

The capsule streams `dd if=/dev/mtdblockN | nc HOST PORT+1+N` for every partition in /proc/mtd,
lowest first. Each stream is a full partition image; losing one means the flash has no way back,
so the receiver writes to a file, fsyncs, and prints the size for the operator log.

  wyze_backup_recv.py --base-port 8446 --slots 8 --dir /tmp/fwbackup
"""
import argparse, os, socket, threading, time


def serve(port, path, done):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    # no accept timeout: the receiver must be listening when assis's installer connects.
    # The old 1800 s timeout expired between camera boots, leaving the ports unbound for
    # minutes at a time — a race against assis's install window (measured 2026-11-05).
    # The LaunchDaemon KeepAlive restarts the process if it exits for any other reason.
    s.settimeout(None)
    # LOOP: the original returned after ONE accept, so the slot's port went
    # UNBOUND forever after the first connection — and assis's installer
    # connects each port once per partition RETRY as well as per run. Measured
    # 2026-11-06: after any single connect, 444-449 sat dead ("connection
    # refused") while the daemon lived on. Serve forever; a new partition
    # capture overwrites the file wholesale (wb), which is the intent.
    while True:
        try:
            c, peer = s.accept()
        except socket.timeout:
            print(f"{port}: no connection", flush=True)
            return
        except OSError as e:
            print(f"{port}: accept failed ({e}) — slot exiting", flush=True)
            return
        # Open lazily: the fleet gate probes every slot with `nc -z`, i.e. connect and
        # close. Opening up front left a 0-byte mtdN.bin behind for every probe, which
        # reads like a truncated backup. Nothing is written until bytes arrive.
        n = 0
        fh = None
        while True:
            d = c.recv(1 << 20)
            if not d:
                break
            if fh is None:
                fh = open(path, "wb")
            fh.write(d)
            n += len(d)
        c.close()
        if fh is None:
            print(f"{port}: connected, no data (file untouched)", flush=True)
            continue
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        print(f"{port}: {n} bytes -> {path}", flush=True)
        done.append((port, n))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-port", type=int, default=8446)
    ap.add_argument("--slots", type=int, default=8)
    ap.add_argument("--dir", default="/tmp/fwbackup")
    a = ap.parse_args()
    os.makedirs(a.dir, exist_ok=True)
    done = []
    ts = []
    for slot in range(a.slots):
        port = a.base_port + 1 + slot
        t = threading.Thread(target=serve, args=(port, os.path.join(a.dir, f"mtd{slot}.bin"), done), daemon=True)
        t.start()
        ts.append(t)
    print(f"listening {a.base_port + 1}..{a.base_port + a.slots} -> {a.dir}", flush=True)
    while True:
        time.sleep(5)
        if done:
            print("received:", sorted(done), flush=True)


if __name__ == "__main__":
    main()
