"""Exercise publication across good, interrupted, and retried native runs."""

import json
from hashlib import sha256
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

module = run_path(str(Path(__file__).with_name("watch-evidence.py")))
publish_take = module["publish_take"]


class NativePublication(unittest.TestCase):
    def test_copied_take_imports_its_own_film_under_the_same_public_url(self):
        with TemporaryDirectory() as directory:
            take = Path(directory) / "intrusion"
            take.mkdir()
            film = take / "gate.mp4"
            film.write_bytes(b"independent recording")
            for location in ("/watch/intrusion/gate.mp4", "gate.mp4", None):
                source, url = module["camera_film"](take, {"id": "gate", "video": location})
                self.assertEqual(source, film)
                self.assertEqual(url, "/watch/intrusion/gate.mp4")

    def test_first_migration_interrupted_at_either_rename(self):
        for failed_file in ("native.json", "native-boxes.json"):
            with self.subTest(failed_file=failed_file), TemporaryDirectory() as directory:
                root = Path(directory)
                take = root / "intrusion"
                stage = root / "objects"
                take.mkdir()
                stage.mkdir()
                summary = take / "native.json"
                alias = take / "native-boxes.json"
                summary.write_text('{"take":"legacy"}')
                alias.write_bytes(b"old boxes")
                replace = Path.replace

                def interrupted(source, target):
                    if target == take / failed_file:
                        raise OSError("interrupted at " + failed_file)
                    return replace(source, target)

                with patch.object(Path, "replace", interrupted), self.assertRaises(OSError):
                    publish_take(take, stage, {"take": "new"}, b"new boxes")
                current = json.loads(summary.read_bytes())
                if failed_file == "native.json":
                    self.assertEqual(current, {"take": "legacy"})
                    self.assertEqual(alias.read_bytes(), b"old boxes")
                else:
                    self.assertEqual(current["take"], "new")
                    self.assertEqual((take / current["detector_boxes"]).read_bytes(), b"new boxes")
                publish_take(take, stage, {"take": "new"}, b"new boxes")
                self.assertEqual(alias.read_bytes(), b"new boxes")
                self.assertEqual(json.loads(summary.read_bytes())["take"], "new")

    def test_previous_generation_stays_readable_until_replacement_is_complete(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            take = root / "intrusion"
            stage = root / "first"
            take.mkdir()
            stage.mkdir()
            original = b"first retained receipt"
            name = sha256(original).hexdigest() + ".txt"
            (stage / name).write_bytes(original)
            old_boxes = b'{"cameras":{"entry":[]}}'
            publish_take(take, stage, {"take": "first"}, old_boxes)
            published = (take / "native.json").read_bytes()
            prior = json.loads(published)
            self.assertEqual((take / prior["detector_boxes"]).read_bytes(), old_boxes)

            stage = root / "second"
            stage.mkdir()
            replacement = b"second retained receipt"
            receipt = sha256(replacement).hexdigest() + ".txt"
            (stage / receipt).write_bytes(b"partial copy")
            new_boxes = b'{"cameras":{"porch":[]}}'
            with self.assertRaisesRegex(ValueError, "Object bytes"):
                publish_take(take, stage, {"take": "second"}, new_boxes)
            self.assertEqual((take / "native.json").read_bytes(), published)
            self.assertEqual((take / "native-boxes.json").read_bytes(), old_boxes)
            self.assertEqual((take / "native/objects" / name).read_bytes(), original)

            (stage / receipt).write_bytes(replacement)
            publish_take(take, stage, {"take": "second"}, new_boxes)
            current = json.loads((take / "native.json").read_bytes())
            self.assertEqual((take / current["detector_boxes"]).read_bytes(), new_boxes)
            self.assertEqual((take / prior["detector_boxes"]).read_bytes(), old_boxes)
            self.assertCountEqual(current["retained_objects"], [
                "native/objects/" + receipt, current["detector_boxes"],
            ])


if __name__ == "__main__":
    unittest.main()
