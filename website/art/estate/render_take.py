"""Render one camera of a staged take to linear EXR frames.

    blender -b build/takes/intrusion.blend -P render_take.py -- \
        --camera gate --frames auto --gpu 0 [--samples 48] [--out DIR]

`--frames` is `auto`, or film-frame ranges such as `0-23,400-430`. Frames already on
disk are skipped, so a second process started with `--reverse` on another GPU
shares the work. The frames folder records which staging and render settings it
was made with, and the script stops if either differs. Needs an NVIDIA card: the
device and the denoiser are OptiX. With `auto` the script renders every film
frame in which a person is in view or something in view is changing. The rest
are held: the script renders one empty plate for each lighting state that has
held frames, and they reuse it. It writes manifest.json naming the EXR behind
every film frame. Film frame f is scene frame 1 + 2 f.
"""
import argparse
import json
import math
import pathlib
import sys
import time

import bpy
import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import plan  # noqa: E402
import takes  # noqa: E402
import render_files  # noqa: E402

PAD = 6  # film frames rendered either side of a person's time in view


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--camera", required=True)
    parser.add_argument("--frames", default="auto")
    parser.add_argument("--gpu", type=int, default=None)
    parser.add_argument("--samples", type=int, default=48)
    parser.add_argument("--out", default=None)
    parser.add_argument("--scale", type=float, default=1.0)
    parser.add_argument("--texture-limit", default="", help="cap texture size, for example 2048, to fit more processes on one GPU")
    parser.add_argument("--reverse", action="store_true", help="work from the last frame back, so two processes can share a camera")
    return parser.parse_args(sys.argv[sys.argv.index("--") + 1:])


def use_gpu(index):
    prefs = bpy.context.preferences.addons["cycles"].preferences
    prefs.compute_device_type = "OPTIX"
    prefs.get_devices()
    cards = [d for d in prefs.devices if d.type == "OPTIX"]
    for device in prefs.devices:
        device.use = False
    for i, device in enumerate(cards):
        device.use = index is None or i == index
    bpy.context.scene.cycles.device = "GPU"


def infrared_cloth():
    """Near infrared: dyed cloth reflects strongly, so dark clothes read pale grey."""
    for material in bpy.data.materials:
        if not material.use_nodes:
            continue
        nodes = material.node_tree.nodes
        if "ir_gamma" in nodes:
            nodes["ir_gamma"].inputs["Gamma"].default_value = 0.74
            for node in nodes:
                if node.name.startswith("tint_"):
                    node.inputs["B"].default_value = (0.3, 0.3, 0.3, 1.0)
        elif material.get("garment"):
            shader = nodes.get("Principled BSDF")
            if shader and not shader.inputs["Base Color"].is_linked:
                shader.inputs["Base Color"].default_value = (0.3, 0.3, 0.3, 1.0)


def lens_model(camera):
    """A camera's entry in the truth file, as the lens model takes.project() works with."""
    lens = camera["lens"]
    model = dict(inverse=np.linalg.inv(np.array(camera["world_from_camera"], dtype=float)))
    if lens["model"] == "rectilinear":
        model.update(kind="rectilinear", hfov=math.radians(lens["hfov"]), vfov=math.radians(lens["vfov"]))
    else:
        model.update(kind="fisheye_equidistant", fov=math.radians(lens["fov"]))
    return model


def sees_gate(camera):
    """Whether the gate, or the ground its leaves swing over, falls inside a camera's frame.

    `camera` is the camera's entry in the truth file, and the projection is the one that
    placed the people's boxes. Whatever stands in the way is ignored, so a camera whose view
    of the gate is blocked counts as seeing it.
    """
    gate = plan.GATE
    half = gate["opening"] / 2
    # Scene axes are (x, -z, height). Each leaf is about half the opening long and swings inside
    # the wall, so the block sampled is the opening wide, that deep and as tall as the piers.
    spots = [(gate["x"] + across, inward - gate["z"], height)
             for across in np.linspace(-half, half, 7) for inward in np.linspace(0.0, half, 4)
             for height in np.linspace(0.0, gate["pillar_height"], 4)]
    u, v, _, valid = takes.project(lens_model(camera), spots)
    return bool((valid & (u >= 0) & (u <= 1) & (v >= 0) & (v <= 1)).any())


def gate_swing(beats, fps, frames):
    """Film frames over which the gate leaves move, with a frame to spare before and two after."""
    return range(max(0, int(beats["gate_starts_closing"] * fps) - 1), min(frames, int(beats["gate_closed"] * fps) + 3))


def wanted_frames(truth, camera):
    """Film frames that must be rendered, and the lighting state of every frame.

    A frame is rendered when a person is in view within PAD frames of it, when the lighting
    is changing, or when the gate is swinging in a frame that takes it in. A person's shadow
    or torch light that reaches the picture while the person is hidden is not looked for.
    """
    frames = truth["clock"]["frames"]
    fps = truth["clock"]["fps"]
    beats = truth["beats"]
    needed = set()
    for rows in truth["boxes"][camera].values():
        for f, box in enumerate(rows):
            if box and box[4] > 0:
                needed.update(range(max(0, f - PAD), min(frames, f + PAD + 1)))
    if sees_gate(next(spec for spec in truth["cameras"] if spec["id"] == camera)):
        needed.update(gate_swing(beats, fps, frames))
    edges = [beats["lights_on"], beats["window_on"], beats["gate_closed"]]
    states = [sum(1 for edge in edges if f / fps >= edge + 0.09) for f in range(frames)]
    # A lighting change is rendered from the frame before it through the first frame that
    # takes the next plate. Stopping one frame after the change left, for some beat times,
    # a held frame between the change and its plate: lit, dark, lit.
    for key in ("lights_on", "window_on"):
        at = int(beats[key] * fps)
        flip = next((f for f in range(frames) if f / fps >= beats[key] + 0.09), frames - 1)
        needed.update(range(max(0, at - 1), min(frames, flip + 1)))
    return sorted(needed), states


def plate_frames(states, needed, swing):
    """The film frame at which each lighting state's empty plate is taken.

    A plate stands in for the held frames of its state, so it is taken at one of them, the
    middle one. It then has exactly their lighting, which the plain middle of a state does
    not promise: the last frame or two of a state can already show the next state's lights.
    For a camera that takes in the gate it has their gate position too, since that camera
    renders the swing frame by frame and holds nothing in it. The other cameras pass over
    held frames inside the swing when they have any outside it. A state with no held frame
    gets no plate: no film frame would show it, and the manifest would not name the file.
    """
    chosen = set(needed)
    moments = {}
    for state in sorted(set(states)):
        held = [f for f, s in enumerate(states) if s == state and f not in chosen]
        pick = [f for f in held if f not in swing] or held
        if pick:
            moments[state] = pick[len(pick) // 2]
    return moments


def main():
    args = arguments()
    scene = bpy.context.scene
    take = scene["take"]
    truth, staging = takes.staged_truth(scene)
    spec = takes.CAMERAS[args.camera]
    out = pathlib.Path(args.out) if args.out else HERE / "build" / "takes" / take / "frames" / args.camera
    out.mkdir(parents=True, exist_ok=True)
    profile = {"camera": args.camera, "samples": args.samples, "scale": args.scale, "texture_limit": args.texture_limit}
    render_files.claim_frames(out, "*.exr", staging, profile)
    use_gpu(args.gpu)
    scene.camera = bpy.data.objects[spec["source"] or f"cam_{args.camera}"]
    scene.render.resolution_x = int(spec["size"][0] * args.scale)
    scene.render.resolution_y = int(spec["size"][1] * args.scale)
    scene.render.resolution_percentage = 100
    scene.render.use_compositing = False
    scene.render.use_persistent_data = True
    scene.render.image_settings.file_format = "OPEN_EXR"
    scene.render.image_settings.color_depth = "16"
    scene.render.image_settings.exr_codec = "ZIP"
    scene.cycles.samples = args.samples
    if args.texture_limit:
        scene.render.use_simplify = True
        scene.cycles.texture_limit_render = args.texture_limit
    scene.cycles.use_adaptive_sampling = True
    scene.cycles.adaptive_threshold = 0.04
    scene.cycles.use_denoising = True
    scene.cycles.denoiser = "OPTIX"
    for obj in bpy.data.objects:
        if obj.name.startswith("ir_"):
            obj.hide_render = obj.name != f"ir_{args.camera}"
    if spec["mode"] == "infrared":
        infrared_cloth()
    people = bpy.data.collections["people"]
    # Only the cast, their props and the gate leaves move. Telling Cycles so spares it
    # from re-reading every mesh of the estate at three instants for each frame.
    moving = set(people.all_objects) | {o for o in bpy.data.objects if o.name.startswith("gate_leaf")}
    for obj in bpy.data.objects:
        if obj not in moving:
            obj.cycles.use_motion_blur = False

    def render(scene_frame, path):
        scene.frame_set(scene_frame)
        started = time.time()
        render_files.render_still(scene, path, bpy.ops.render.render)
        return time.time() - started

    frames = truth["clock"]["frames"]
    if args.frames == "auto":
        needed, states = wanted_frames(truth, args.camera)
    else:
        needed = []
        for part in args.frames.split(","):
            a, _, b = part.partition("-")
            needed.extend(range(int(a), int(b or a) + 1))
        states = None
    times = []
    for f in (reversed(needed) if args.reverse else needed):
        path = out / f"f{f:04d}.exr"
        if not path.exists():
            times.append(render(1 + 2 * f, path))
            print(f"FRAME {args.camera} {f} {times[-1]:.1f}s", flush=True)
    manifest = None
    if states is not None:
        # One empty plate for each lighting state in which a frame is held.
        people.hide_render = True
        plates = {}
        swing = gate_swing(truth["beats"], truth["clock"]["fps"], frames)
        for state, moment in plate_frames(states, needed, swing).items():
            path = out / f"plate{state}.exr"
            if not path.exists():
                times.append(render(1 + 2 * moment, path))
                print(f"PLATE {args.camera} {state} {times[-1]:.1f}s", flush=True)
            plates[state] = path.name
        people.hide_render = False
        chosen = set(needed)
        manifest = dict(camera=args.camera, samples=args.samples, rendered=sorted(chosen),
                        files=[f"f{f:04d}.exr" if f in chosen else plates[states[f]] for f in range(frames)],
                        truth_sha256=staging, profile=profile)
        manifest["file_sha256"] = {name: render_files.file_digest(out / name) for name in sorted(set(manifest["files"]))}
        render_files.write_text(out / "manifest.json", json.dumps(manifest) + "\n")
    if times:
        print(f"DONE {args.camera} {len(times)} renders, mean {sum(times) / len(times):.1f}s, total {sum(times) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
