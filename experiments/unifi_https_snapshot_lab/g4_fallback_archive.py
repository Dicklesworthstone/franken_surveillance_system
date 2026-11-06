#!/usr/bin/env python3
"""Copy closed G4 staging segments to an owner-scoped local fallback archive.

This transitional host tool is independent of the FSS native recorder. It
never deletes staging originals. Destination publication is create-only and
occurs only after a full content hash and a second read of the staged copy.
"""
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

STAGING = Path('/data/unifi-g4-recording-staging')
MOUNT = Path('/bulk')
PARENT = Path('/bulk/unifi_camera_recordings')
DIRECTORY = 'g4-instant-fallback'
MARKER = b'FSS G4 fallback archive v1\n'
NAME = re.compile(r'^g4-\d{8}T\d{6}Z-[0-9a-f]{8}-\d{8}T\d{6}\.mp4$')
PARTIAL = re.compile(r'^\.partial-[0-9a-f]{32}$')
RETENTION = 30 * 24 * 60 * 60
MIN_AGE = 120
MAX_FILE = 2 * 1024 * 1024 * 1024
MAX_FILES = 32
BLOCK = 1024 * 1024


def snapshot(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def digest_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while chunk := os.read(fd, BLOCK):
        h.update(chunk)
    return h.digest()


def source_idle(path):
    """Refuse an open file or any ambiguous fuser/probe outcome."""
    try:
        use = subprocess.run(['/usr/bin/fuser', '-s', str(path)], capture_output=True, timeout=20)
        if use.returncode == 0:
            return False
        if use.returncode != 1 or use.stderr:
            return None
        result = subprocess.run(
            ['/usr/bin/ffprobe', '-v', 'error', '-show_entries', 'format=duration',
             '-of', 'default=noprint_wrappers=1:nokey=1', str(path)],
            capture_output=True, text=True, timeout=20,
        )
        duration = float(result.stdout.strip())
        return result.returncode == 0 and math.isfinite(duration) and duration >= 1
    except ValueError:
        return False
    except (OSError, subprocess.SubprocessError):
        return None


def archive_directory(parent, mount):
    if not os.path.ismount(mount):
        raise RuntimeError('fallback_mount_unavailable')
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(parent_fd).st_dev != os.stat(mount, follow_symlinks=False).st_dev:
            raise RuntimeError('fallback_mount_changed')
        created = False
        try:
            os.mkdir(DIRECTORY, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise RuntimeError('fallback_directory_not_private')
            if created:
                marker = os.open('.fss-g4-archive', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                with os.fdopen(marker, 'wb') as out:
                    out.write(MARKER)
                    out.flush()
                    os.fsync(out.fileno())
                os.fsync(fd)
                os.fsync(parent_fd)
            marker = os.open('.fss-g4-archive', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(marker, 'rb') as inp:
                if inp.read(128) != MARKER:
                    raise RuntimeError('fallback_marker_mismatch')
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent_fd)


def copy_segment(staging, name, archive_fd, now, idle=source_idle):
    if not NAME.fullmatch(name):
        return 'skipped'
    path = staging / name
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_FILE
                or not MIN_AGE <= now - info.st_mtime < RETENTION):
            return 'skipped'
        readiness = idle(path)
        if readiness is None:
            return 'error'
        if not readiness:
            return 'skipped'
        source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (FileNotFoundError, ValueError):
        return 'skipped'
    except OSError:
        return 'error'
    partial = '.partial-' + uuid.uuid4().hex
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or snapshot(before) != snapshot(info):
            return 'skipped'
        try:
            existing = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=archive_fd)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            try:
                target = os.fstat(existing)
                if not stat.S_ISREG(target.st_mode) or target.st_size != before.st_size:
                    return 'conflict'
                same = digest_fd(source) == digest_fd(existing)
                return 'present' if same and snapshot(os.fstat(source)) == snapshot(before) else 'conflict'
            finally:
                os.close(existing)
        temp = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=archive_fd)
        try:
            h = hashlib.sha256()
            left = before.st_size
            while left:
                chunk = os.read(source, min(BLOCK, left))
                if not chunk:
                    raise RuntimeError('source_changed')
                h.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(temp, view)
                    if written <= 0:
                        raise RuntimeError('partial_write')
                    view = view[written:]
                left -= len(chunk)
            if snapshot(os.fstat(source)) != snapshot(before):
                raise RuntimeError('source_changed')
            os.utime(temp, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.fsync(temp)
        finally:
            os.close(temp)
        verify = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=archive_fd)
        try:
            if digest_fd(verify) != h.digest():
                raise RuntimeError('copy_hash_mismatch')
        finally:
            os.close(verify)
        if snapshot(path.lstat()) != snapshot(before):
            raise RuntimeError('source_changed')
        os.close(source)
        source = None
        readiness = idle(path)
        if readiness is None:
            raise RuntimeError('probe_unavailable')
        if not readiness or snapshot(path.lstat()) != snapshot(before):
            raise RuntimeError('source_reopened_or_changed')
        try:
            os.link(partial, name, src_dir_fd=archive_fd, dst_dir_fd=archive_fd, follow_symlinks=False)
        except FileExistsError:
            return 'conflict'
        os.fsync(archive_fd)
        return 'copied'
    except FileNotFoundError:
        return 'skipped'
    except RuntimeError as error:
        return 'skipped' if str(error) in ('source_changed', 'source_reopened_or_changed') else 'error'
    except OSError:
        return 'error'
    finally:
        if source is not None:
            os.close(source)
        try:
            os.unlink(partial, dir_fd=archive_fd)
        except FileNotFoundError:
            pass


def prune(archive_fd, now):
    removed = 0
    for name in os.listdir(archive_fd):
        if not (NAME.fullmatch(name) or PARTIAL.fullmatch(name)):
            continue
        info = os.stat(name, dir_fd=archive_fd, follow_symlinks=False)
        age = RETENTION if NAME.fullmatch(name) else 7 * 86400
        if stat.S_ISREG(info.st_mode) and now - info.st_mtime >= age:
            os.unlink(name, dir_fd=archive_fd)
            removed += 1
    if removed:
        os.fsync(archive_fd)
    return removed


def run(staging=STAGING, parent=PARENT, mount=MOUNT, idle=source_idle, now=None):
    now = time.time() if now is None else now
    fd = archive_directory(parent, mount)
    try:
        lock = os.open('.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            removed = prune(fd, now)
            counts = {'copied': 0, 'present': 0, 'conflict': 0, 'skipped': 0, 'error': 0}
            attempts = 0
            for name in sorted(os.listdir(staging)):
                if not NAME.fullmatch(name):
                    continue
                try:
                    source_info = (staging / name).lstat()
                except FileNotFoundError:
                    counts['skipped'] += 1
                    continue
                if (not stat.S_ISREG(source_info.st_mode) or source_info.st_size <= 0
                        or source_info.st_size > MAX_FILE
                        or not MIN_AGE <= now - source_info.st_mtime < RETENTION):
                    counts['skipped'] += 1
                    continue
                try:
                    target_info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    target_info = None
                if target_info is not None:
                    if (stat.S_ISREG(source_info.st_mode) and stat.S_ISREG(target_info.st_mode)
                            and source_info.st_size == target_info.st_size
                            and source_info.st_mtime_ns == target_info.st_mtime_ns):
                        # The create-only publication was hash-verified on the
                        # earlier pass; this is only a metadata check now.
                        counts['present'] += 1
                    else:
                        counts['conflict'] += 1
                    continue
                if attempts >= MAX_FILES:
                    break
                attempts += 1
                counts[copy_segment(staging, name, fd, now, idle)] += 1
            return counts, removed
        finally:
            os.close(lock)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        counts, removed = run()
        status = 'deferred' if counts['conflict'] or counts['error'] else 'complete'
        print(('fallback_archive=' + status + ' copied={copied} present={present} conflict={conflict} skipped={skipped} error={error} pruned={}').format(removed, **counts))
        if counts['conflict'] or counts['error']:
            sys.exit(1)
    except (OSError, RuntimeError) as error:
        print('fallback_archive=deferred category=' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
