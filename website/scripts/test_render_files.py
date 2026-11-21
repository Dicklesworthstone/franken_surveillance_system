"""Run with python3 -B website/scripts/test_render_files.py."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "art/estate"))
import render_files as files  # noqa: E402


class FrameLifecycle(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name)
        self.profile = {"camera": "gate", "samples": 48}

    def claim(self, digest):
        return files.claim_frames(self.path, "*.exr", digest, self.profile)

    def simultaneous(self, values):
        barrier = threading.Barrier(len(values))
        def claim(digest):
            barrier.wait()
            try:
                return self.claim(digest)
            except SystemExit:
                return None
        with concurrent.futures.ThreadPoolExecutor(len(values)) as pool:
            return list(pool.map(claim, values))

    def test_concurrent_forward_and_reverse_accept_only_one_generation(self):
        digests = [hashlib.sha256(bytes([i % 2])).hexdigest() for i in range(12)]
        results = self.simultaneous(digests)
        chosen = json.loads((self.path / "staging.json").read_bytes())["truth_sha256"]
        self.assertEqual(results, [d if d == chosen else None for d in digests])
        self.assertEqual(self.simultaneous([chosen] * 12), [chosen] * 12)
        self.assertEqual(sorted(p.name for p in self.path.iterdir()), ["staging.json"])
        with self.assertRaises(SystemExit):
            files.claim_frames(self.path, "*.exr", chosen, {"camera": "porch", "samples": 48})

    def test_old_raw_frames_require_prior_evidence(self):
        frame = self.path / "f0000.exr"
        frame.write_bytes(b"legacy frame")
        with self.assertRaises(SystemExit):
            self.claim("old-staging")
        self.assertFalse((self.path / "staging.json").exists())
        manifest = {"truth_sha256": "old-staging", "profile": self.profile, "files": []}
        file = self.path / "manifest.json"
        file.write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit):
            self.claim("old-staging")
        manifest["files"] = [frame.name]
        manifest["file_sha256"] = {frame.name: hashlib.sha256(b"different historical picture").hexdigest()}
        file.write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit):
            self.claim("old-staging")
        manifest["file_sha256"][frame.name] = hashlib.sha256(frame.read_bytes()).hexdigest()
        file.write_text(json.dumps(manifest))
        self.assertEqual(self.claim("old-staging"), "old-staging")
        self.assertEqual(frame.read_bytes(), b"legacy frame")

    def test_failed_encoder_is_reaped_and_previous_output_survives(self):
        target = self.path / "test.mp4"
        target.write_bytes(b"previous completed film")
        ffmpeg = ["ffmpeg", "-v", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                  "-video_size", "16x16", "-framerate", "1", "-i", "pipe:0", "-c:v", "libx264"]
        with self.assertRaisesRegex(RuntimeError, "source read failed"):
            with files.encode_raw(target, ffmpeg) as stream:
                stream.write(bytes(16 * 16 * 3))
                raise RuntimeError("source read failed")
        self.assertEqual(target.read_bytes(), b"previous completed film")
        self.assertEqual(list(self.path.iterdir()), [target])
        with files.encode_raw(target, ffmpeg) as stream:
            stream.write(bytes(16 * 16 * 3))
        frames = subprocess.check_output(["ffprobe", "-v", "error", "-count_frames", "-show_entries",
                                         "stream=nb_read_frames", "-of", "csv=p=0", target], text=True)
        self.assertEqual(frames.strip(), "1")

    def test_blender_cancel_keeps_partial_frames_out_of_the_resume_set(self):
        scene = SimpleNamespace(render=SimpleNamespace(filepath="existing scene setting"))
        target = self.path / "f0007.exr"
        def cancel(**kwargs):
            self.assertTrue(kwargs["write_still"])
            Path(scene.render.filepath).write_bytes(b"unfinished render")
            return {"CANCELLED"}
        with self.assertRaisesRegex(RuntimeError, "did not finish"):
            files.render_still(scene, target, cancel)
        self.assertFalse(target.exists())
        target.write_bytes(b"finished earlier")
        with self.assertRaisesRegex(RuntimeError, "did not finish"):
            files.render_still(scene, target, cancel)
        self.assertEqual(scene.render.filepath, "existing scene setting")
        self.assertEqual(target.read_bytes(), b"finished earlier")
        self.assertEqual(list(self.path.iterdir()), [target])

    def test_two_film_developers_and_a_failed_retry(self):
        # Exercise the real entry point, two frame workers, FFmpeg, and the published report.
        code = self.path / "art/estate"
        code.mkdir(parents=True)
        for name in ["camera_looks.py", "render_files.py"]:
            shutil.copyfile(Path(files.__file__).with_name(name), code / name)
        takes = code / "build/takes"
        frames = takes / "fixture/frames/gate"
        frames.mkdir(parents=True)
        truth = {"clock": {"fps": 6, "start": "2026-01-01T00:00:00Z", "frames": 6},
                 "cameras": [{"id": "gate", "mode": "infrared", "width": 320, "height": 180, "clock_offset_s": 0}]}
        raw = json.dumps(truth).encode()
        (takes / "fixture.truth.json").write_bytes(raw)
        staging = {"truth_sha256": hashlib.sha256(raw).hexdigest(), "profile": {"camera": "gate", "samples": 1}}
        (frames / "staging.json").write_text(json.dumps(staging))
        subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=6", "-frames:v", "6",
                        "-pix_fmt", "gbrpf32le", "-threads", "1", "-start_number", "0", frames / "f%04d.exr"], check=True)
        out = self.path / "published"
        report = takes / "fixture/looks/gate.json"
        def start(crf):
            return subprocess.Popen([sys.executable, "-B", code / "camera_looks.py", "fixture", "--cameras",
                                     "gate", "--workers", "2", "--crf", str(crf), "--out", out])
        first, second = start(20), start(40)
        self.assertEqual([first.wait(), second.wait()], [0, 0])
        result = json.loads(report.read_bytes())
        self.assertIn(result["crf"], (20, 40))
        self.assertEqual(result["video_sha256"], files.file_digest(out / "gate.mp4"))
        self.assertEqual(result["poster_sha256"], files.file_digest(out / "gate.jpg"))
        (frames / "f0002.exr").write_bytes(b"ordinary incomplete EXR")
        self.assertNotEqual(start(20).wait(), 0)
        self.assertEqual(files.file_digest(out / "gate.mp4"), result["video_sha256"])
        self.assertEqual(files.file_digest(out / "gate.jpg"), result["poster_sha256"])
        self.assertEqual(json.loads(report.read_bytes()), result)
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["gate.jpg", "gate.mp4"])


if __name__ == "__main__":
    unittest.main()
