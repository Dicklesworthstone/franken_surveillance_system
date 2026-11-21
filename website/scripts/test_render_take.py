"""Run with python3 -B website/scripts/test_render_take.py.

render_take.py's choice of frames, checked outside Blender against the published take in
public/watch/intrusion/scene.json: which frames each camera renders, which cameras take in
the gate, and where the empty plates are taken. Blender's own modules are replaced by empty
stand-ins when they are not installed; nothing tested here calls them.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import types
import unittest

import numpy as np

WEBSITE = Path(__file__).resolve().parents[1]
for _name in ("bpy", "bmesh", "mathutils"):
    try:
        __import__(_name)
    except ImportError:
        sys.modules[_name] = types.ModuleType(_name)
        sys.modules[_name].Matrix = sys.modules[_name].Vector = object
sys.path.insert(0, str(WEBSITE / "art/estate"))
import plan  # noqa: E402
import render_take  # noqa: E402
import takes  # noqa: E402

TAKE = WEBSITE / "public/watch/intrusion"
SCENE = json.loads((TAKE / "scene.json").read_bytes())
FPS, FRAMES = SCENE["clock"]["fps"], SCENE["clock"]["frames"]
CAMERAS = {camera["id"]: camera for camera in SCENE["cameras"]}
EMPTY = dict(SCENE, boxes={name: {} for name in CAMERAS})  # the same take with nobody in any picture


def frames_in(spans):
    return {f for first, last in spans for f in range(first, last + 1)}


def lighting(beats, f):
    """What the staged scene shows at film frame f: (floods on, upstairs window on, gate position).

    takes.step_key() holds the old level until the scene frame before a light's key and the new
    one from the key on, and the gate turns only between its two keys. Film frame f is scene
    frame 1 + 2 f.
    """
    at = 1 + 2 * f
    opened, shut = takes.take_frame(beats["gate_starts_closing"]), takes.take_frame(beats["gate_closed"])
    gate = "open" if at <= opened else "shut" if at >= shut else "moving"
    return at >= takes.take_frame(beats["lights_on"]), at >= takes.take_frame(beats["window_on"]), gate


def timings():
    """The take with nobody in view and its events moved about, close together and far apart."""
    for start in np.arange(0.05, 52.0, 0.17):
        for window_after, gate_after in ((1.7, 13.4), (1.7, 3.0), (1.7, 0.2), (0.2, 0.4), (0.1, -2.0), (0.3, -6.0)):
            closing = start + gate_after
            beats = dict(SCENE["beats"], lights_on=round(float(start), 2), window_on=round(float(start + window_after), 2),
                         gate_starts_closing=round(float(closing), 2), gate_closed=round(float(closing + 5.0), 2))
            if closing > 0.2 and beats["gate_closed"] + 0.3 < FRAMES / FPS:
                yield dict(EMPTY, beats=beats)
    # A lighting change one held frame after the take starts or after the gate shuts: the
    # state before it is four frames long and its last two already show the new lights.
    for lights, window, closing in ((0.17, 1.87, 20.0), (0.18, 0.4, 20.0), (13.92, 15.6, 8.5), (13.93, 14.1, 8.5),
                                    (30.0, 30.17, 24.6), (30.01, 30.19, 24.59)):
        yield dict(EMPTY, beats=dict(SCENE["beats"], lights_on=lights, window_on=window,
                                     gate_starts_closing=closing, gate_closed=closing + 5.0))


class FrameChoice(unittest.TestCase):
    def test_lens_model_puts_people_inside_their_own_boxes(self):
        inside = 0
        for name, camera in CAMERAS.items():
            model = render_take.lens_model(camera)
            for actor, track in SCENE["tracks"].items():
                present = [f for f in range(FRAMES) if track["x"][f] is not None]
                hips = [(track["x"][f], -track["z"][f], 0.95) for f in present]
                u, v, _, valid = takes.project(model, hips)
                for i, f in enumerate(present):
                    if not (valid[i] and 0 <= u[i] <= 1 and 0 <= v[i] <= 1):
                        continue
                    box = SCENE["boxes"][name][actor][f]
                    self.assertIsNotNone(box, f"{name} {actor} frame {f}: in frame by the lens model, no box in the take")
                    self.assertTrue(box[0] - 0.02 <= u[i] <= box[2] + 0.02 and box[1] - 0.02 <= v[i] <= box[3] + 0.02,
                                    f"{name} {actor} frame {f}: hips at {u[i]:.3f}, {v[i]:.3f}, box {box}")
                    inside += 1
        self.assertGreater(inside, 4000)

    def test_every_camera_but_the_one_facing_away_takes_in_the_gate(self):
        self.assertEqual({name: render_take.sees_gate(camera) for name, camera in CAMERAS.items()},
                         dict(gate=True, driveway=True, doorbell=True, porch=True, entry=False))

    def test_frames_wanted_are_the_published_ones_plus_the_doorbell_gate_frames(self):
        # The published doorbell film was rendered when only `gate` and `driveway` counted as
        # taking in the gate, and holds these seven frames of its swing on a plate. Films from
        # a new render hold none of them: `late` is then empty, and the last test here, which
        # measures those seven frames in the film, goes.
        late = {"doorbell": set(range(656, 663))}
        # Lighting states in which each camera holds frames, and so takes a plate. The driveway
        # camera has someone in view throughout. Rendering those seven frames leaves the doorbell
        # nothing held between the upstairs light and the gate shutting, state 2.
        plates = dict(gate=[0, 2, 3], driveway=[], doorbell=[0, 3], porch=[3], entry=[0, 2, 3])
        for name, camera in CAMERAS.items():
            needed, states = render_take.wanted_frames(SCENE, name)
            self.assertEqual(len(states), FRAMES)
            swing = render_take.gate_swing(SCENE["beats"], FPS, FRAMES)
            self.assertEqual(sorted(render_take.plate_frames(states, needed, swing)), plates[name], name)
            self.assertEqual(set(needed) - frames_in(camera["rendered_spans"]), late.get(name, set()), name)
            self.assertEqual(frames_in(camera["rendered_spans"]) - set(needed), set(), name)
            self.assertEqual(frames_in(camera["held_spans"]) - late.get(name, set()), set(range(FRAMES)) - set(needed), name)

    def test_held_frames_of_a_state_share_one_lighting_and_plates_are_taken_among_them(self):
        seen = {name: render_take.sees_gate(camera) for name, camera in CAMERAS.items()}
        cases = held_total = 0
        for scene in [SCENE, *timings()]:
            beats = scene["beats"]
            swing = render_take.gate_swing(beats, FPS, FRAMES)
            for name in CAMERAS:
                needed, states = render_take.wanted_frames(scene, name)
                chosen = set(needed)
                plates = render_take.plate_frames(states, needed, swing)
                where = f"{name}, lights {beats['lights_on']}, window {beats['window_on']}, gate {beats['gate_starts_closing']}"
                self.assertEqual(set(plates), {states[f] for f in range(FRAMES) if f not in chosen},
                                 f"{where}: a plate for each state with held frames and for no other")
                for state, plate in plates.items():
                    held = [f for f in range(FRAMES) if states[f] == state and f not in chosen]
                    # A camera that does not take in the gate cannot tell where the gate is.
                    look = (lambda f: lighting(beats, f)) if seen[name] else (lambda f: lighting(beats, f)[:2])
                    self.assertEqual(len({look(f) for f in held}), 1, f"{where}: held frames of state {state} differ among themselves")
                    self.assertNotEqual(lighting(beats, held[0])[2] if seen[name] else "", "moving", f"{where}: a frame is held while the gate moves")
                    self.assertIn(plate, held, f"{where}: the plate of state {state} is not one of the frames it stands in for")
                    held_total += len(held)
                cases += 1
        self.assertGreater(cases, 5000)
        self.assertGreater(held_total, 1_000_000)

    @unittest.skipUnless(shutil.which("ffmpeg"), "needs ffmpeg")
    def test_published_doorbell_film_shows_nothing_at_its_held_gate_frames(self):
        # The picture round the gate, from the lens model, in the encoded film's luma.
        camera = CAMERAS["doorbell"]
        gate, half = plan.GATE, plan.GATE["opening"] / 2
        ends = [(gate["x"] + side, -gate["z"], height) for side in (-half, half) for height in (0.0, gate["pillar_height"])]
        u, v, _, valid = takes.project(render_take.lens_model(camera), ends)
        self.assertTrue(valid.all())
        width, height = camera["width"], camera["height"]
        x0, x1 = int(u.min() * width) - 12, int(u.max() * width) + 12
        y0, y1 = int(v.min() * height) - 12, int(v.max() * height) + 12
        first, last = 636, 683
        # Seeking to just before film frame `first` makes it the first picture written.
        raw = subprocess.run(["ffmpeg", "-v", "error", "-ss", f"{(first - 0.5) / FPS:.4f}", "-i", str(TAKE / "doorbell.mp4"),
                              "-frames:v", str(last - first + 1), "-f", "rawvideo", "-pix_fmt", "yuv420p", "-"],
                             check=True, stdout=subprocess.PIPE).stdout
        size = width * height * 3 // 2
        self.assertEqual(len(raw), size * (last - first + 1))
        patch = [np.frombuffer(raw, dtype=np.uint8, count=width * height, offset=i * size).reshape(height, width)[y0:y1, x0:x1].astype(np.float32)
                 for i in range(last - first + 1)]
        step = {first + i: float(np.abs(patch[i] - patch[i - 1]).mean()) for i in range(1, len(patch))}
        # Film frames 656 to 662 are the held ones; 672 starts a group of pictures.
        for edge in (656, 663):
            self.assertLess(step[edge], 0.5, f"mean luma change entering film frame {edge}")
            self.assertLess(step[edge], step[672] / 4, f"film frame {edge} against the keyframe")


if __name__ == "__main__":
    unittest.main()
