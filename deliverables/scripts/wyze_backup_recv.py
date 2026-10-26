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
    s.settimeout(1800)
    try:
        c, peer = s.accept()
    except socket.timeout:
        print(f"{port}: no connection", flush=True)
        return
    n = 0
    with open(path, "wb") as fh:
        while True:
            d = c.recv(1 << 20)
            if not d:
                break
            fh.write(d)
            n += len(d)
        fh.flush()
        os.fsync(fh.fileno())
    c.close()
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
