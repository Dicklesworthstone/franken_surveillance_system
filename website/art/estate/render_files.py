"""Publication and generation checks shared by Blender and the offline film developer."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


# Before the staged Blender scene carried the digest of its truth, this particular pair
# produced the archived five-camera film. Other unlabelled staging pairs are unverified.
LEGACY_TRUTH = "92a9f263c02a0b50e19154e344fb033ad03a3ef6406c53358b6644dd82332157"


@contextmanager
def output_file(target):
    """Keep partial writes out of the published filename, including during concurrent jobs."""
    target = Path(target)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".fss-render-") as folder:
        scratch = Path(folder) / target.name
        yield scratch
        if not scratch.is_file() or scratch.stat().st_size == 0:
            raise RuntimeError(f"No complete output was written for {target}")
        scratch.replace(target)


def write_text(target, data):
    with output_file(target) as scratch:
        scratch.write_text(data)


@contextmanager
def publication_lock(path):
    """Serialize the short commit of related files for one take or one camera."""
    # The inode stays in the private build directory. Removing it would let two waiters
    # acquire different locks for the same destination.
    with open(path, "a+b") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def render_still(scene, target, render):
    old = scene.render.filepath
    try:
        with output_file(target) as scratch:
            scene.render.filepath = str(scratch)
            if "FINISHED" not in render(write_still=True):
                raise RuntimeError(f"Blender did not finish {target}")
    finally:
        scene.render.filepath = old


def check_record(record, digest, label):
    if record.get("truth_sha256") != digest:
        raise SystemExit(f"{label}: missing or different staging. Use a fresh frame directory.")


def claim_frames(folder, pattern, digest, profile):
    """Publish the first complete claim without replacement. Concurrent losers check its bytes."""
    folder = Path(folder)
    record = folder / "staging.json"
    expected = {"truth_sha256": digest, "profile": profile}
    if not record.exists():
        if any(folder.glob(pattern)):
            # A saved manifest explicitly identifying the generation can migrate its frame set.
            # The absence of a version number in an unrelated truth file proves nothing.
            manifest = folder / "manifest.json"
            if not record.exists():
                old = json.loads(manifest.read_bytes()) if manifest.exists() else {}
                if any(old.get(k) != v for k, v in expected.items()):
                    raise SystemExit(f"{folder}: existing frames have no matching staging and render settings.")
                hashes = old.get("file_sha256", {})
                for frame in folder.glob(pattern):
                    if frame.name not in old.get("files", []) or hashes.get(frame.name) != file_digest(frame):
                        raise SystemExit(f"{folder}: no matching prior checksum for {frame.name}.")
        with tempfile.TemporaryDirectory(dir=folder, prefix=".fss-render-") as tmp:
            ready = Path(tmp) / "claim"
            ready.write_text(json.dumps(expected) + "\n")
            try:
                os.link(ready, record)
            except FileExistsError:
                pass
    if json.loads(record.read_bytes()) != expected:
        raise SystemExit(f"{folder}: frame staging or render settings differ. Use a fresh frame directory.")
    return digest


@contextmanager
def encode_raw(target, argv):
    """Drain or stop the encoder before its private output is published or discarded."""
    with output_file(target) as scratch:
        with subprocess.Popen([*argv, str(scratch)], stdin=subprocess.PIPE) as proc:
            try:
                yield proc.stdin
                proc.stdin.close()
                if proc.wait() != 0:
                    raise RuntimeError(f"FFmpeg failed for {target}")
            finally:
                if proc.poll() is None:
                    proc.kill()
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
                proc.wait()


def file_digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
