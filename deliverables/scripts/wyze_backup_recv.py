#!/usr/bin/env python3
"""Receive the per-partition backup streams upgraderun.sh sends before it writes anything.

The capsule streams `dd if=/dev/mtdblockN | nc HOST PORT+1+N` for every partition in /proc/mtd,
lowest first. Each stream is a full partition image; losing one means the flash has no way back,
so the receiver writes atomically (tmp + fsync + rename), archives any distinct previous capture
rather than clobbering it, computes SHA-256 on the fly, and updates an atomic manifest.json.

  wyze_backup_recv.py --base-port 443 --slots 16 \\
      --dir ~/projects/franken_surveillance_system/flash-images/wyze-hl_cam4/live-capture
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import socket
import threading
import time

MANIFEST_SCHEMA = "fss.flash_backup_manifest.v1"


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_compact() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class ManifestWriter:
    """Thread-safe atomic writer for backup capture manifest.json."""

    def __init__(self, manifest_path: str, family: str, backup_dir: str):
        self.manifest_path = os.path.abspath(manifest_path)
        self.family = family
        self.backup_dir = os.path.abspath(backup_dir)
        self._lock = threading.Lock()
        self._partitions: dict[str, dict] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        if not os.path.isfile(self.manifest_path):
            return
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            parts = doc.get("partitions") if isinstance(doc, dict) else None
            if isinstance(parts, dict):
                self._partitions = parts
        except (OSError, json.JSONDecodeError):
            pass

    def record(
        self,
        slot: int,
        filename: str,
        size_bytes: int,
        sha256: str,
        peer_ip: str,
        port: int,
    ) -> None:
        with self._lock:
            key = f"mtd{slot}"
            self._partitions[key] = {
                "slot": slot,
                "filename": filename,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "peer_ip": peer_ip,
                "port": port,
                "received_at_utc": _utc_now(),
            }
            ordered = dict(sorted(self._partitions.items(), key=lambda kv: kv[1].get("slot", 0)))
            complete_slots = [v["slot"] for v in ordered.values() if v.get("size_bytes", 0) > 0]
            total_bytes = sum(int(v.get("size_bytes", 0)) for v in ordered.values())
            payload = {
                "schema_version": MANIFEST_SCHEMA,
                "family": self.family,
                "dir": self.backup_dir,
                "updated_at_utc": _utc_now(),
                "partitions": ordered,
                "total_bytes": total_bytes,
                "complete_slots": complete_slots,
            }
            parent = os.path.dirname(self.manifest_path)
            os.makedirs(parent, exist_ok=True)
            tmp_path = f"{self.manifest_path}.tmp.{os.getpid()}.{threading.get_ident()}"
            try:
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, sort_keys=False)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_path, self.manifest_path)
            except BaseException:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                raise


def _archive_if_distinct(path: str, new_sha256: str, backup_dir: str, slot: int) -> str | None:
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None
    old_sha = _sha256_file(path)
    if old_sha == new_sha256:
        return None
    hist_dir = os.path.join(backup_dir, "history")
    os.makedirs(hist_dir, exist_ok=True)
    dest = os.path.join(hist_dir, f"{_utc_compact()}-mtd{slot}-{old_sha[:12]}.bin")
    shutil.copy2(path, dest)
    return dest


def _bind_listener(bind_host: str, port: int, stop_event: threading.Event | None) -> tuple[socket.socket, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind_host, port))
        actual_port = s.getsockname()[1]
        s.listen(4)
        # no accept timeout in daemon mode; short poll when stop_event is supplied (tests/drills)
        s.settimeout(0.2 if stop_event is not None else None)
    except BaseException:
        try:
            s.close()
        except OSError:
            pass
        raise
    return s, actual_port


def serve(
    port: int,
    path: str,
    done: list,
    slot: int = 0,
    manifest: ManifestWriter | None = None,
    archive_existing: bool = True,
    bind_host: str = "0.0.0.0",
    stop_event: threading.Event | None = None,
    ready_cb=None,
    sock: socket.socket | None = None,
) -> None:
    if sock is None:
        s, actual_port = _bind_listener(bind_host, port, stop_event)
    else:
        s = sock
        actual_port = s.getsockname()[1]
    if ready_cb is not None:
        ready_cb(slot, actual_port)
    backup_dir = os.path.dirname(os.path.abspath(path))
    filename = os.path.basename(path)
    # Serve forever: assis's installer connects per partition retry as well as per run.
    try:
        while stop_event is None or not stop_event.is_set():
            try:
                c, peer = s.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if stop_event is None or not stop_event.is_set():
                    print(f"{actual_port}: accept failed ({e}) — slot exiting", flush=True)
                return
            # Open lazily: the fleet gate probes every slot with `nc -z` (connect + close).
            # Nothing is written until bytes actually arrive.
            n = 0
            fh = None
            part_path = None
            recv_err: BaseException | None = None
            hasher = hashlib.sha256()
            peer_ip = peer[0] if peer else ""
            try:
                c.settimeout(60.0)
                while True:
                    d = c.recv(1 << 20)
                    if not d:
                        break
                    if fh is None:
                        os.makedirs(backup_dir, exist_ok=True)
                        part_path = os.path.join(
                            backup_dir,
                            f".{filename}.part.{os.getpid()}.{threading.get_ident()}",
                        )
                        fh = open(part_path, "wb")
                    fh.write(d)
                    hasher.update(d)
                    n += len(d)
            except (OSError, TimeoutError) as e:
                recv_err = e
            finally:
                try:
                    c.close()
                except OSError:
                    pass
            if recv_err is not None:
                if fh is not None:
                    try:
                        fh.close()
                    except OSError:
                        pass
                if part_path and os.path.exists(part_path):
                    try:
                        os.unlink(part_path)
                    except OSError:
                        pass
                print(
                    f"{actual_port}: connection aborted after {n} bytes ({recv_err}) — partial discarded, slot still listening",
                    flush=True,
                )
                continue
            if fh is None:
                print(f"{actual_port}: connected, no data (file untouched)", flush=True)
                continue
            try:
                fh.flush()
                os.fsync(fh.fileno())
                fh.close()
                fh = None
                digest = hasher.hexdigest()
                if archive_existing:
                    archived = _archive_if_distinct(path, digest, backup_dir, slot)
                    if archived:
                        print(f"{actual_port}: archived previous mtd{slot} -> {archived}", flush=True)
                os.replace(part_path, path)
                part_path = None
            except OSError as e:
                if fh is not None:
                    try:
                        fh.close()
                    except OSError:
                        pass
                if part_path and os.path.exists(part_path):
                    try:
                        os.unlink(part_path)
                    except OSError:
                        pass
                print(f"{actual_port}: failed committing backup ({e}) — slot still listening", flush=True)
                continue
            if manifest is not None:
                manifest.record(
                    slot=slot,
                    filename=filename,
                    size_bytes=n,
                    sha256=digest,
                    peer_ip=peer_ip,
                    port=actual_port,
                )
            print(f"{actual_port}: {n} bytes sha256={digest} -> {path}", flush=True)
            done.append((actual_port, n, digest))
    finally:
        try:
            s.close()
        except OSError:
            pass


class BackupServer:
    """Manage a multi-slot backup receiver cleanly (used by drills and unit tests)."""

    def __init__(
        self,
        backup_dir: str,
        base_port: int = 8446,
        slots: int = 6,
        family: str = "wyze-hl_cam4",
        manifest_path: str | None = None,
        bind_host: str = "127.0.0.1",
        archive_existing: bool = True,
    ):
        self.backup_dir = os.path.abspath(backup_dir)
        self.base_port = base_port
        self.slots = slots
        self.family = family
        self.manifest_path = manifest_path or os.path.join(self.backup_dir, "manifest.json")
        self.bind_host = bind_host
        self.archive_existing = archive_existing
        self.done: list = []
        self.ports: dict[int, int] = {}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._ready = threading.Event()
        self._ready_lock = threading.Lock()
        self.manifest = ManifestWriter(self.manifest_path, self.family, self.backup_dir)

    def _on_ready(self, slot: int, actual_port: int) -> None:
        with self._ready_lock:
            self.ports[slot] = actual_port
            if len(self.ports) == self.slots:
                self._ready.set()

    def start(self, timeout: float = 5.0) -> None:
        os.makedirs(self.backup_dir, exist_ok=True)
        # Bind all slot sockets synchronously first so any EADDRINUSE / OSError
        # propagates immediately to callers (e.g. port-range search) without
        # leaking half-bound slots or stalling until timeout.
        bound: list[tuple[int, socket.socket, int]] = []
        try:
            for slot in range(self.slots):
                port = (self.base_port + 1 + slot) if self.base_port > 0 else 0
                sock, actual_port = _bind_listener(self.bind_host, port, self._stop)
                bound.append((slot, sock, actual_port))
        except BaseException:
            for _, sock, _ in bound:
                try:
                    sock.close()
                except OSError:
                    pass
            raise

        for slot, sock, actual_port in bound:
            t = threading.Thread(
                target=serve,
                kwargs={
                    "port": actual_port,
                    "path": os.path.join(self.backup_dir, f"mtd{slot}.bin"),
                    "done": self.done,
                    "slot": slot,
                    "manifest": self.manifest,
                    "archive_existing": self.archive_existing,
                    "bind_host": self.bind_host,
                    "stop_event": self._stop,
                    "ready_cb": self._on_ready,
                    "sock": sock,
                },
                daemon=True,
            )
            t.start()
            self._threads.append(t)
        if not self._ready.wait(timeout):
            self.stop()
            raise RuntimeError("BackupServer failed to start all slot threads within timeout")

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-port", type=int, default=8446)
    ap.add_argument("--slots", type=int, default=8)
    ap.add_argument("--dir", default="/tmp/fwbackup")
    ap.add_argument("--manifest", default=None, help="Path to atomic JSON manifest (default: <dir>/manifest.json)")
    ap.add_argument("--family", default="wyze-hl_cam4", help="Camera family label for manifest")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    ap.add_argument("--no-archive-existing", action="store_true", help="Do not archive distinct prior captures")
    a = ap.parse_args()
    os.makedirs(a.dir, exist_ok=True)
    manifest_path = a.manifest or os.path.join(a.dir, "manifest.json")
    manifest = ManifestWriter(manifest_path, a.family, a.dir)
    done = []
    # Pre-bind every slot synchronously so port conflicts fail fast instead of
    # leaving a partially deaf daemon.
    bound: list[tuple[int, socket.socket, int]] = []
    try:
        for slot in range(a.slots):
            port = a.base_port + 1 + slot
            sock, actual_port = _bind_listener(a.bind, port, None)
            bound.append((slot, sock, actual_port))
    except BaseException:
        for _, sock, _ in bound:
            try:
                sock.close()
            except OSError:
                pass
        raise
    ts = []
    for slot, sock, actual_port in bound:
        t = threading.Thread(
            target=serve,
            kwargs={
                "port": actual_port,
                "path": os.path.join(a.dir, f"mtd{slot}.bin"),
                "done": done,
                "slot": slot,
                "manifest": manifest,
                "archive_existing": not a.no_archive_existing,
                "bind_host": a.bind,
                "sock": sock,
            },
            daemon=True,
        )
        t.start()
        ts.append(t)
    print(f"listening {a.base_port + 1}..{a.base_port + a.slots} -> {a.dir} (manifest={manifest_path})", flush=True)
    while True:
        time.sleep(5)
        if done:
            print("received:", sorted((p, n) for p, n, _ in done), flush=True)


if __name__ == "__main__":
    main()
