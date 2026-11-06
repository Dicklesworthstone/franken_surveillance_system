#!/usr/bin/env python3
"""Synthetic filesystem tests for the transitional fallback archive."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import g4_fallback_archive as archive


def filename(index):
    return 'g4-20200101T000000Z-' + format(index, '08x') + '-20200101T000000.mp4'


class FallbackArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fss-fallback-test-', dir='/bulk/unifi_camera_recordings')
        self.root = Path(self.temp.name)
        self.staging = self.root / 'staging'
        self.parent = self.root / 'archive-parent'
        self.staging.mkdir()
        self.parent.mkdir()
        self.now = time.time()
        self.idle = lambda _: True

    def tearDown(self):
        self.temp.cleanup()

    def source(self, index, content=b'synthetic video', age=300):
        path = self.staging / filename(index)
        path.write_bytes(content)
        os.utime(path, (self.now - age, self.now - age))
        return path

    def run_archive(self, idle=None):
        return archive.run(self.staging, self.parent, Path('/bulk'), idle or self.idle, self.now)

    def test_copy_preserves_source_and_conflicts_do_not_overwrite(self):
        source = self.source(1)
        counts, _ = self.run_archive()
        target = self.parent / archive.DIRECTORY / source.name
        self.assertEqual(counts['copied'], 1)
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.assertTrue(source.exists())
        target.write_bytes(b'different')
        counts, _ = self.run_archive()
        self.assertEqual(counts['conflict'], 1)
        self.assertEqual(target.read_bytes(), b'different')
        self.assertTrue(source.exists())

    def test_backlog_advances_past_existing_copies(self):
        for index in range(40):
            self.source(index, str(index).encode())
        first, _ = self.run_archive()
        second, _ = self.run_archive()
        self.assertEqual(first['copied'], 32)
        self.assertEqual(second['copied'], 8)
        self.assertEqual(second['present'], 32)
        self.assertEqual(len(list(self.staging.iterdir())), 40)

    def test_expired_staging_backlog_does_not_block_recent_segments(self):
        for index in range(40):
            self.source(index, b'old', age=31 * 86400)
        recent = self.source(40, b'current')
        counts, _ = self.run_archive()
        self.assertEqual(counts['copied'], 1)
        self.assertEqual(counts['skipped'], 40)
        self.assertEqual((self.parent / archive.DIRECTORY / recent.name).read_bytes(), b'current')

    def test_open_or_changed_source_is_not_published(self):
        source = self.source(1)
        counts, _ = self.run_archive(lambda _: False)
        self.assertEqual(counts['skipped'], 1)
        calls = 0

        def change_on_second_probe(_):
            nonlocal calls
            calls += 1
            if calls == 2:
                source.write_bytes(b'changed while copied')
            return True

        counts, _ = self.run_archive(change_on_second_probe)
        target = self.parent / archive.DIRECTORY / source.name
        self.assertEqual(counts['skipped'], 1)
        self.assertFalse(target.exists())
        self.assertEqual(source.read_bytes(), b'changed while copied')
        self.assertFalse(any(p.name.startswith('.partial-') for p in target.parent.iterdir()))

    def test_publication_io_failure_is_reported_and_preserves_source(self):
        source = self.source(1)
        with patch.object(archive.os, 'link', side_effect=OSError('synthetic failure')):
            counts, _ = self.run_archive()
        target = self.parent / archive.DIRECTORY / source.name
        self.assertEqual(counts['error'], 1)
        self.assertTrue(source.exists())
        self.assertFalse(target.exists())
        self.assertFalse(any(p.name.startswith('.partial-') for p in target.parent.iterdir()))

    def test_unavailable_file_probe_is_reported_and_preserves_source(self):
        source = self.source(1)
        counts, _ = self.run_archive(lambda _: None)
        self.assertEqual(counts['error'], 1)
        self.assertTrue(source.exists())
        self.assertFalse((self.parent / archive.DIRECTORY / source.name).exists())

    def test_retention_only_removes_matching_old_regular_files(self):
        self.run_archive()
        folder = self.parent / archive.DIRECTORY
        expired, unrelated = folder / filename(1), folder / 'unrelated.mp4'
        old_dir, old_link, target = folder / filename(2), folder / filename(3), folder / 'target'
        expired.write_bytes(b'old')
        unrelated.write_bytes(b'keep')
        target.write_bytes(b'keep')
        old_dir.mkdir()
        old_link.symlink_to(target)
        for path in (expired, unrelated, target, old_dir):
            os.utime(path, (self.now - 31 * 86400, self.now - 31 * 86400))
        os.utime(old_link, (self.now - 31 * 86400, self.now - 31 * 86400), follow_symlinks=False)
        _, removed = self.run_archive()
        self.assertEqual(removed, 1)
        self.assertFalse(expired.exists())
        self.assertTrue(unrelated.exists() and target.exists() and old_dir.is_dir() and old_link.is_symlink())

    def test_missing_mount_refuses_before_creating_archive(self):
        self.source(1)
        with self.assertRaises(RuntimeError):
            archive.run(self.staging, self.parent, self.root / 'not-a-mount', self.idle, self.now)
        self.assertFalse((self.parent / archive.DIRECTORY).exists())

    def test_symlink_source_is_not_copied(self):
        original = self.root / 'other'
        original.write_bytes(b'keep')
        (self.staging / filename(1)).symlink_to(original)
        counts, _ = self.run_archive()
        self.assertEqual(counts['skipped'], 1)
        self.assertEqual(original.read_bytes(), b'keep')
        self.assertFalse((self.parent / archive.DIRECTORY / filename(1)).exists())


if __name__ == '__main__':
    unittest.main()
