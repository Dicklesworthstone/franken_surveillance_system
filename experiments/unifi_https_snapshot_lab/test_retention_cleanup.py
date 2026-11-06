#!/usr/bin/env python3
"""Exercise the installed G4 cleanup against synthetic files, never recordings.

Run on the recorder host with permission to read the upload program. The
installed cleanup is parsed, and only its volume and folder assignments are
redirected to an owned temporary directory before it is executed. The script
does not prove that the scheduled upload or cleanup ran at any particular time.
"""
import ast
import contextlib
import hashlib
import io
import os
import pathlib
import tempfile
import time

source = pathlib.Path('/data/unifi-g4-recorder/app/g4-upload.py').read_text()
outer = ast.parse(source)
parts = [n.value for n in ast.walk(outer)
         if isinstance(n, ast.Constant) and isinstance(n.value, str)
         and 'mtime' in n.value and '30' in n.value]
if len(parts) != 1:
    raise SystemExit('cleanup_source_not_unique')
if hashlib.sha256(parts[0].encode()).hexdigest() != '8cd83f8e363d73e54d958d41f47b8396698d1b89c772492a3bc9d64903801bf3':
    raise SystemExit('cleanup_source_changed_review_before_running')
with tempfile.TemporaryDirectory(prefix='fss-retention-fixture-') as name:
    folder = pathlib.Path(name)

    class Redirect(ast.NodeTransformer):
        def __init__(self, volume):
            self.replaced = set()
            self.volume = volume

        def visit_Assign(self, node):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                key = node.targets[0].id
                if key == 'volume':
                    self.replaced.add(key)
                    node.value = ast.Constant(self.volume)
                if key == 'folder':
                    self.replaced.add(key)
                    node.value = ast.parse('pathlib.Path(' + repr(name) + ')', mode='eval').body
            return node

    def redirected(volume):
        transform = Redirect(volume)
        tree = ast.fix_missing_locations(transform.visit(ast.parse(parts[0])))
        if transform.replaced != {'volume', 'folder'}:
            raise SystemExit('cleanup_redirect_refused')
        return compile(tree, '<isolated-retention>', 'exec')

    def filename(index):
        return folder / ('g4-20200101T000000Z-' + format(index, '08x')
                         + '-20200101T000000.mp4')

    now = time.time()
    recent, expired, link, directory = (filename(i) for i in range(1, 5))
    unrelated, target = folder / 'unrelated.mp4', folder / 'link-target'
    for item in (recent, expired, unrelated, target):
        item.write_bytes(b'synthetic')
    os.utime(recent, (now - 29 * 86400, now - 29 * 86400))
    os.utime(expired, (now - 30 * 86400 - 5, now - 30 * 86400 - 5))
    os.utime(unrelated, (now - 31 * 86400, now - 31 * 86400))
    os.utime(target, (now - 31 * 86400, now - 31 * 86400))
    link.symlink_to(target)
    directory.mkdir()
    os.utime(link, (now - 31 * 86400, now - 31 * 86400), follow_symlinks=False)
    os.utime(directory, (now - 31 * 86400, now - 31 * 86400))
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            exec(redirected(str(folder / 'missing-mount')), {})
    except SystemExit:
        unmounted_refused = expired.exists()
    else:
        unmounted_refused = False
    with contextlib.redirect_stdout(io.StringIO()):
        exec(redirected('/'), {})
    checks = {
        'unmounted_refused_before_deletion': unmounted_refused,
        'recent_kept': recent.exists(),
        'expired_removed': not expired.exists(),
        'unrelated_kept': unrelated.exists(),
        'symlink_kept': link.is_symlink(),
        'directory_kept': directory.is_dir(),
        'link_target_kept': target.exists(),
    }
    for key, value in checks.items():
        print(key + '=' + str(value).lower())
    if not all(checks.values()):
        raise SystemExit('retention_fixture_failed')
