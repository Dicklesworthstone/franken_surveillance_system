"""Render one camera of a staged take to linear EXR frames.

    blender -b build/takes/intrusion.blend -P render_take.py -- \
        --camera gate --frames auto --gpu 0 [--samples 48] [--out DIR]

`--frames` is `auto`, or film-frame ranges such as `0-23,400-430`. Frames already on
disk are skipped, so a second process started with `--reverse` on another GPU
shares the work. The frames folder records which staging it was rendered from and
the script stops if the take has been staged again since. Needs an NVIDIA card:
the device and the denoiser are OptiX. With `auto`
the script renders every film frame in which a person is in view or something
in view is changing, plus one empty plate per lighting state; held frames
reuse the plate. It writes manifest.json naming the EXR behind every film
frame. Film frame f is scene frame 1 + 2 f.
"""
import argparse
import json
import pathlib
import sys
import time

import bpy

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import takes  # noqa: E402
import render_files  # noqa: E402

PAD = 6  # film frames rendered either side of a person's time in view
SEES_GATE = {"gate", "driveway"}


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


def wanted_frames(truth, camera):
    """Film frames that must be rendered, and the lighting state of every frame."""
    frames = truth["clock"]["frames"]
    fps = truth["clock"]["fps"]
    beats = truth["beats"]
    needed = set()
    for rows in truth["boxes"][camera].values():
        for f, box in enumerate(rows):
            if box and box[4] > 0:
                needed.update(range(max(0, f - PAD), min(frames, f + PAD + 1)))
    if camera in SEES_GATE:
        needed.update(range(max(0, int(beats["gate_starts_closing"] * fps) - 1), min(frames, int(beats["gate_closed"] * fps) + 3)))
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
        # One empty plate per lighting state, taken at a moment inside that state.
        people.hide_render = True
        plates = {}
        for state in sorted(set(states)):
            members = [f for f in range(frames) if states[f] == state]
            path = out / f"plate{state}.exr"
            if not path.exists():
                times.append(render(1 + 2 * members[len(members) // 2], path))
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
