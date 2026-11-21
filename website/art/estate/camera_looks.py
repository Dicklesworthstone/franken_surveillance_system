"""Turn rendered EXR frames into consumer-camera footage.

    python3 -B camera_looks.py intrusion [--cameras gate,porch] [--frames 60-90 --preview DIR]
    python3 -B camera_looks.py intrusion --scene

Each camera gets a simple sensor model: auto exposure with a time constant, a
clipping tone curve, colour or infrared monochrome, noise regenerated every
frame, lens softness with in-camera sharpening, vignetting and a burned-in
clock showing that camera's own time. With no --frames each named camera is
encoded to public/watch/<take>/<camera>.mp4 with a poster, and a report and
contact sheet are left in build/takes/<take>/looks/. Cameras can be developed
in separate processes; --scene then merges the reports, the scripted truth
and the twin mapping into scene.json. With no --cameras everything runs in
one go. With --frames the looked frames are written as JPEGs for review.

Reading a frame and bringing it to a log-encoded sensor signal happens in
worker processes; exposure, tone, glow, noise, sharpening and the clock are
applied in order in the main process. Needs numpy, Pillow and ffmpeg.
"""
import argparse
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager, nullcontext
import datetime
import functools
import hashlib
import json
from itertools import islice
import os
import pathlib
import subprocess
import tempfile

import render_files

# One thread per process: frames are spread over worker processes, and threaded BLAS stalls on a busy machine.
for _name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_name, "1")

import numpy as np  # noqa: E402
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
PUBLIC = HERE.parent.parent / "public" / "watch"
FONTS = "/usr/share/fonts/truetype/"

# key: the mean level auto exposure aims for; gain: its limits; white: where highlights clip;
# toe: shadow contrast (above 1 pulls dim areas toward black, as a small sensor does at night);
# noise and chroma: grain and colour blotch at eight times gain, as a fraction of full scale.
LOOKS = {
    "gate": dict(key=0.13, tau=0.5, gain=(0.3, 10.0), noise=0.03, soft=0.9, sharpen=0.7, vignette=0.34, white=9.0, toe=1.1, bloom=0.92,
                 osd=dict(corner="top-left", font="dejavu/DejaVuSansMono-Bold.ttf", size=22, form="%Y-%m-%d %H:%M:%S", tag="CAM 01")),
    "driveway": dict(key=0.06, tau=0.7, gain=(0.3, 8.0), noise=0.03, chroma=0.012, saturation=0.72, soft=0.8, sharpen=0.5,
                     vignette=0.22, white=3.5, toe=1.18, bloom=0.82, balance=(1.04, 1.0, 0.94),
                     osd=dict(corner="top-right", font="liberation/LiberationSans-Bold.ttf", size=23, form="%m/%d/%Y %I:%M:%S %p", tag=None)),
    "doorbell": dict(key=0.075, tau=0.4, gain=(0.3, 7.0), noise=0.03, chroma=0.012, saturation=0.8, soft=1.0, sharpen=0.8,
                     vignette=0.0, white=3.0, toe=1.25, bloom=0.82, balance=(1.0, 1.0, 1.02), circle=True,
                     osd=dict(corner="top-left", font="liberation/LiberationSans-Regular.ttf", size=19, form="%I:%M:%S %p\n%b %d %Y", tag=None)),
    "porch": dict(key=0.06, tau=0.6, gain=(0.3, 8.0), noise=0.028, chroma=0.012, saturation=0.82, soft=0.7, sharpen=0.6,
                  vignette=0.26, white=3.5, toe=1.18, bloom=0.82, balance=(1.02, 1.0, 0.97),
                  osd=dict(corner="top-left", font="liberation/LiberationMono-Bold.ttf", size=21, form="%Y/%m/%d %H:%M:%S", tag="Front Porch")),
    "entry": dict(key=0.13, tau=0.5, gain=(0.3, 10.0), noise=0.032, soft=1.0, sharpen=0.6, vignette=0.4, white=9.0, toe=1.1, bloom=0.92,
                  osd=dict(corner="top-right", font="dejavu/DejaVuSans-Bold.ttf", size=20, form="%d-%m-%Y %a %H:%M:%S", tag=None)),
}

# Attribution the page must show wherever the films appear.
CREDITS = [
    dict(role="Intruder", work="Eric Rigged 001 - Rigged 3D Business Man", author="Renderpeople", licence="CC BY 4.0",
         url="https://sketchfab.com/3d-models/a46bc9f67aaa415bb4f3241eef900e7f", licence_url="https://creativecommons.org/licenses/by/4.0/",
         changes="Shirt and tie recoloured through the supplied garment masks; whole colour map darkened by 20%; mesh subdivided once; cap, backpack and torch added; body driven by CMU motion capture; for the two infrared films the colour map is lifted (gamma 0.74) and the garment tints set to mid grey."),
    dict(role="Lookout", work="Nathan Animated 003 - Walking 3D Man", author="Renderpeople", licence="CC BY 4.0",
         url="https://sketchfab.com/3d-models/143a2b1ea5eb4385ae90a73657aca3bc", licence_url="https://creativecommons.org/licenses/by/4.0/",
         changes="T-shirt recoloured through the supplied garment mask; whole colour map darkened by 10%; mesh subdivided once; body driven by CMU motion capture; for the two infrared films the colour map is lifted (gamma 0.74) and the garment tint set to mid grey."),
    dict(role="Motion", work="CMU Graphics Lab Motion Capture Database", author="Carnegie Mellon University", licence="Free to use; created with funding from NSF EIA-0196217",
         url="http://mocap.cs.cmu.edu", changes="BVH conversion by Bruce Hahne; clips looped along site paths, joined and retargeted."),
]

# Takes staged before takes.STAGING existed keyed the torch to fade from torch_on to torch_off,
# and their truth file words it as a switch. Films rendered from them show the fade, so the
# scene file says what the films show. A truth file with a `staging` entry is used as written.
FADING_TORCH = {
    "torch_on": "The intruder switches on a hand torch at the door. In these films the beam then fades, reaching dark at torch_off",
    "torch_off": "The torch beam, fading since torch_on, reaches dark as the intruder runs",
}

LUMA = np.array([0.2126, 0.7152, 0.0722], dtype=np.float32)
INFRARED = np.array([0.42, 0.42, 0.16], dtype=np.float32)
# The sensor signal travels from workers as 16-bit codes of log2(signal) over this range.
LOG_LOW, LOG_HIGH = -14.0, 6.0
CODES = 65535.0 / (LOG_HIGH - LOG_LOW)


def read_exr(path, width, height):
    """Linear RGB float32 (H, W, 3) through ffmpeg's EXR decoder."""
    raw = subprocess.run(["ffmpeg", "-v", "error", "-threads", "1", "-i", str(path), "-threads", "1", "-f", "rawvideo", "-pix_fmt", "gbrpf32le", "-"],
                         check=True, stdout=subprocess.PIPE).stdout
    planes = np.frombuffer(raw, dtype="<f4").reshape(3, height, width)
    return np.stack([planes[2], planes[0], planes[1]], axis=-1)


@functools.lru_cache(maxsize=8)
def optics(name, width, height):
    """Per-pixel lens falloff, the exposure meter's weights and, for the fisheye, its image circle."""
    look = LOOKS[name]
    yy, xx = np.mgrid[0:height, 0:width].astype(np.float32)
    cx, cy = (width - 1) / 2, (height - 1) / 2
    radius = np.sqrt(((xx - cx) / cx) ** 2 + ((yy - cy) / cy) ** 2) / 2 ** 0.5
    falloff = (1.0 - look["vignette"] * radius ** 2 * 2.0).clip(0.1, 1.0)[..., None].astype(np.float32)
    centre = np.exp(-((xx - cx) / (0.55 * cx)) ** 2 - ((yy - cy * 1.1) / (0.6 * cy)) ** 2)
    meter = (centre / centre.sum()).astype(np.float32)
    circle = None
    if look.get("circle"):
        edge = np.sqrt(((xx - cx) / (cx + 0.5)) ** 2 + ((yy - cy) / (cy + 0.5)) ** 2)
        circle = Image.fromarray((np.clip((1.0 - edge) * cx / 1.5, 0.0, 1.0) * 255).astype(np.uint8))
    return falloff, meter, circle


@functools.lru_cache(maxsize=6)
def plate(path, width, height):
    return read_exr(path, width, height)


def prepare(task):
    """Worker: one frame to (metered level, log-coded sensor signal, unit noise)."""
    name, mono, path, held, width, height, seed = task
    look = LOOKS[name]
    linear = plate(path, width, height) if held else read_exr(path, width, height)
    falloff, meter, _ = optics(name, width, height)
    luminance = linear @ LUMA
    metered = float((np.minimum(luminance, 2.0 * float(np.median(luminance)) + 0.05) * meter).sum())
    if mono:
        signal = (linear @ INFRARED)[..., None] * falloff
    else:
        # White balance and saturation as one colour matrix on the linear signal.
        s = look["saturation"]
        matrix = (s * np.eye(3, dtype=np.float32) + (1.0 - s) * np.tile(LUMA, (3, 1))) * np.array(look["balance"], dtype=np.float32)[:, None]
        signal = (linear @ matrix.T.astype(np.float32)) * falloff
    np.maximum(signal, 2.0 ** LOG_LOW, out=signal)
    np.log2(signal, out=signal)
    signal -= LOG_LOW
    signal *= CODES
    code = np.minimum(signal, 65535.0).astype(np.uint16)
    rng = np.random.default_rng(seed)
    grain = rng.standard_normal((height, width, 1), dtype=np.float32)
    if not mono:
        small = rng.standard_normal((height // 4 + 1, width // 4 + 1, 3), dtype=np.float32)
        small -= small.mean(axis=-1, keepdims=True)
        blotch = np.repeat(np.repeat(small, 4, axis=0), 4, axis=1)[:height, :width]
        grain = grain + blotch * (look["chroma"] / look["noise"])
    # Unit noise as bytes: one standard deviation is 24 levels around 128.
    noise = np.clip(grain * 24.0 + 128.0, 0.0, 255.0).astype(np.uint8)
    return metered, code, noise


class Sensor:
    """Exposure, tone and finishing for one camera, applied frame by frame in order."""

    def __init__(self, name, spec, clock):
        self.name, self.spec, self.look = name, spec, LOOKS[name]
        self.width, self.height = spec["width"], spec["height"]
        self.mono = spec["mode"] == "infrared"
        self.gain = None
        self.start = datetime.datetime.fromisoformat(clock["start"])
        self.fps = clock["fps"]
        self.circle = optics(name, self.width, self.height)[2]
        osd = self.look["osd"]
        self.font = ImageFont.truetype(FONTS + osd["font"], osd["size"])
        self.rects = []
        self.levels = np.exp2(np.arange(65536, dtype=np.float32) / CODES + LOG_LOW)
        threshold = int(self.look["bloom"] * 255)
        self.glow_table = [min(255, int(max(0, v - threshold) * 3.2)) for v in range(256)] * (1 if self.mono else 3)

    def task(self, folder, filename, frame):
        seed = (sum(ord(c) for c in self.name) * 7919 + frame * 104729) % (2 ** 32)
        return (self.name, self.mono, str(folder / filename), filename.startswith("plate"), self.width, self.height, seed)

    def expose(self, metered):
        """Auto exposure: ease the gain toward the level that brings the metered mean to the key."""
        low, high = self.look["gain"]
        wanted = float(np.clip(self.look["key"] / max(metered, 1e-5), low, high))
        if self.gain is None:
            self.gain = wanted
        else:
            self.gain += (wanted - self.gain) * (1.0 - np.exp(-1.0 / self.fps / self.look["tau"]))
        return self.gain

    def develop(self, prepared, frame):
        metered, code, noise = prepared
        look = self.look
        gain = self.expose(metered)
        # Gain, the clipping tone curve, the shadow toe and the display transfer as one table over the coded signal.
        x = self.levels * gain
        white = look["white"]
        y = np.power(np.clip(x * (1.0 + x / (white * white)) / (1.0 + x), 0.0, 1.0), look["toe"])
        y = np.where(y <= 0.0031308, 12.92 * y, 1.055 * np.power(y, 1 / 2.4) - 0.055)
        table = (np.clip(y, 0.0, 1.0) * 255.0 + 0.5).astype(np.uint8)
        pixels = table[code]
        image = Image.fromarray(pixels[..., 0] if self.mono else pixels)
        # Highlights bleed a little: a cheap lens and a small sensor.
        glow = image.resize((self.width // 4, self.height // 4), Image.BOX).point(self.glow_table)
        glow = glow.filter(ImageFilter.GaussianBlur(1.75)).resize((self.width, self.height), Image.BILINEAR)
        image = ImageChops.add(image, glow)
        # Noise grows with the gain the camera is using.
        amount = look["noise"] * float(np.clip(gain / 8.0, 0.35, 2.2)) ** 0.5 * 255.0 / 24.0
        scale = [int(min(255, max(0, 128 + (v - 128) * amount))) for v in range(256)]
        grain = Image.fromarray(noise[..., 0] if self.mono else noise).point(scale * (1 if self.mono else 3))
        image = ImageChops.add(image, grain, 1, -128)
        image = image.filter(ImageFilter.GaussianBlur(look["soft"]))
        image = image.filter(ImageFilter.UnsharpMask(radius=2, percent=int(look["sharpen"] * 100), threshold=0))
        if self.mono:
            image = image.convert("RGB")
        if self.circle is not None:
            image = ImageChops.multiply(image, Image.merge("RGB", (self.circle,) * 3))
        self.stamp(image, frame)
        return image

    def stamp(self, image, frame):
        """Burn in this camera's clock; remember the rectangle it covers."""
        osd = self.look["osd"]
        now = self.start + datetime.timedelta(seconds=frame / self.fps + self.spec["clock_offset_s"])
        text = now.strftime(osd["form"])
        if osd["tag"]:
            text = f"{text}\n{osd['tag']}"
        draw = ImageDraw.Draw(image)
        box = draw.multiline_textbbox((0, 0), text, font=self.font, spacing=4, stroke_width=2)
        width, height = box[2] - box[0], box[3] - box[1]
        margin = 14
        x = margin if osd["corner"].endswith("left") else self.width - margin - width
        y = margin
        draw.multiline_text((x - box[0], y - box[1]), text, font=self.font, fill=(238, 238, 238), spacing=4,
                            stroke_width=2, stroke_fill=(12, 12, 12), align="left" if osd["corner"].endswith("left") else "right")
        # The rectangle is the union over the take, padded: text width changes as digits change.
        pad = 8
        left, top = max(0, x - pad), max(0, y - pad)
        right, bottom = min(self.width, x + width + pad), min(self.height, y + height + pad)
        if self.rects:
            old = self.rects[0]
            left, top = min(left, old[0]), min(top, old[1])
            right, bottom = max(right, old[0] + old[2]), max(bottom, old[1] + old[3])
        self.rects = [[int(left), int(top), int(right - left), int(bottom - top)]]


def frames_for(take, camera, root=None):
    folder = pathlib.Path(root) / camera if root else HERE / "build" / "takes" / take / "frames" / camera
    manifest = json.loads((folder / "manifest.json").read_text()) if (folder / "manifest.json").exists() else None
    return folder, manifest


def read_truth(take):
    """The scripted truth and the SHA-256 of its file, which names one staging of the take."""
    raw = (HERE / "build" / "takes" / f"{take}.truth.json").read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


@contextmanager
def prepared_frames(tasks, workers):
    """Deliver frames in order; cancel queued work and drain active FFmpeg readers on failure."""
    source = iter(tasks)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        pending = deque(pool.submit(prepare, job) for job in islice(source, workers))

        def ordered():
            while pending:
                yield pending.popleft().result()
                job = next(source, None)
                if job is not None:
                    pending.append(pool.submit(prepare, job))
        try:
            yield ordered()
        finally:
            for handle in pending:
                handle.cancel()


def run(take, cameras, frames, preview, root=None, out=None, crf=33, workers=6):
    """Develop the named cameras (all when empty). Encoding a film also leaves a
    report and a contact sheet under build/takes/<take>/looks/ for the scene step."""
    truth, digest = read_truth(take)
    clock = truth["clock"]
    out = pathlib.Path(out) if out else PUBLIC / take
    out.mkdir(parents=True, exist_ok=True)
    looks = HERE / "build" / "takes" / take / "looks"
    looks.mkdir(parents=True, exist_ok=True)
    for spec in truth["cameras"]:
        name = spec["id"]
        if cameras and name not in cameras:
            continue
        folder, manifest = frames_for(take, name, root)
        if not folder.exists():
            print("SKIPPED", name, "has no frames at", folder, flush=True)
            continue
        if not frames and not preview:
            # A film is about to be published; review JPEGs may be developed from anything.
            record = folder / "staging.json"
            bound = json.loads(record.read_bytes()) if record.exists() else {}
            render_files.check_record(bound, digest, name)
            if (bound.get("profile") or {}).get("camera") != name:
                raise SystemExit(f"{name}: frame directory belongs to a different or unknown camera.")
            if manifest is not None:
                render_files.check_record(manifest, digest, name)
                if manifest.get("profile") != bound["profile"]:
                    raise SystemExit(f"{name}: manifest and frames use different render settings.")
        sensor = Sensor(name, spec, clock)
        wanted = frames or list(range(clock["frames"]))
        tasks = [sensor.task(folder, manifest["files"][f] if manifest else f"f{f:04d}.exr", f) for f in wanted]
        encoding = not frames and not preview
        with tempfile.TemporaryDirectory(dir=out, prefix=".fss-render-") as tmp:
            stage = pathlib.Path(tmp)
            film, poster_file = stage / f"{name}.mp4", stage / f"{name}.jpg"
            command = ["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{sensor.width}x{sensor.height}",
                       "-r", str(clock["fps"]), "-i", "-", "-an", "-c:v", "libx264", "-preset", "slow", "-crf", str(crf),
                       "-g", "48", "-keyint_min", "48", "-sc_threshold", "0", "-bf", "0", "-pix_fmt", "yuv420p", "-movflags", "+faststart"]
            sheet = []
            poster = None
            encoder = render_files.encode_raw(film, command) if encoding else nullcontext()
            with encoder as pipe, prepared_frames(tasks, min(workers, len(tasks))) as prepared:
                for f, pixels in zip(wanted, prepared):
                    image = sensor.develop(pixels, f)
                    if pipe:
                        pipe.write(image.tobytes())
                        if poster is None:
                            poster = image.copy()
                        if f % (2 * clock["fps"]) == 0:
                            sheet.append(image.resize((480, round(480 * sensor.height / sensor.width))))
                    else:
                        target = pathlib.Path(preview or folder) / f"{name}-{f:04d}.jpg"
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with render_files.output_file(target) as scratch:
                            image.save(scratch, quality=90)
                        print("PREVIEW", target, "gain", round(sensor.gain, 2), flush=True)
            if encoding:
                poster.save(poster_file, quality=86)
                columns = 6
                rows = (len(sheet) + columns - 1) // columns
                w, h = sheet[0].size
                tiled = Image.new("RGB", (w * columns, h * rows))
                for i, tile in enumerate(sheet):
                    tiled.paste(tile, ((i % columns) * w, (i // columns) * h))
                report = dict(osd=sensor.rects, rendered=manifest["rendered"] if manifest else wanted, crf=crf,
                              samples=(manifest or {}).get("samples"), truth_sha256=digest,
                              video_sha256=render_files.file_digest(film), poster_sha256=render_files.file_digest(poster_file))
                with render_files.publication_lock(looks / f".{name}.publish.lock"):
                    with render_files.output_file(looks / f"{name}-sheet.jpg") as scratch:
                        tiled.save(scratch, quality=84)
                    film.replace(out / film.name)
                    poster_file.replace(out / poster_file.name)
                    render_files.write_text(looks / f"{name}.json", json.dumps(report) + "\n")
                print("FILM", out / film.name, (out / film.name).stat().st_size, "bytes", flush=True)
    return truth, out


def spans(frames):
    """Sorted frame numbers to inclusive [first, last] runs."""
    runs = []
    for f in frames:
        if runs and f == runs[-1][1] + 1:
            runs[-1][1] = f
        else:
            runs.append([f, f])
    return runs


def write_scene(take, out=None):
    """Merge the scripted truth with the published films into scene.json."""
    truth, digest = read_truth(take)
    out = pathlib.Path(out) if out else PUBLIC / take
    looks = HERE / "build" / "takes" / take / "looks"
    frames = set(range(truth["clock"]["frames"]))
    samples = set()
    archived = None
    historic_cameras = 0
    for camera in truth["cameras"]:
        name = camera["id"]
        report = json.loads((looks / f"{name}.json").read_text())
        samples.add(report.get("samples"))
        data = (out / f"{name}.mp4").read_bytes()
        film_digest = hashlib.sha256(data).hexdigest()
        if report.get("video_sha256") is not None:
            render_files.check_record(report, digest, name)
            if (report["video_sha256"] != film_digest
                    or report.get("poster_sha256") != render_files.file_digest(out / f"{name}.jpg")):
                raise SystemExit(f"{name}: the film or poster differs from the developer's report.")
        else:
            # The historical five films predate developer bindings. Only their exact published
            # camera imports and original display geometry can use the known legacy truth.
            if take != "intrusion" or digest != render_files.LEGACY_TRUTH:
                raise SystemExit(f"{name}: no verified film and staging in the developer's report.")
            if archived is None:
                archived = (json.loads((PUBLIC / take / "native.json").read_bytes()),
                            json.loads((PUBLIC / take / "scene.json").read_bytes()))
            imports, old_scene = archived
            old = next(c for c in old_scene["cameras"] if c["id"] == name)
            if (imports["cameras"][name]["custody"].get("sha256") != "sha256:" + film_digest
                    or old["video_sha256"] != film_digest or old["osd"] != report["osd"]
                    or old["rendered_spans"] != spans(report["rendered"])
                    or report.get("truth_sha256", digest) != digest):
                raise SystemExit(f"{name}: film or developer report differs from the archived take.")
            historic_cameras += 1
        camera.update(video=f"/watch/{take}/{name}.mp4", poster=f"/watch/{take}/{name}.jpg",
                      video_bytes=len(data), video_sha256=film_digest,
                      osd=report["osd"], rendered_spans=spans(report["rendered"]),
                      held_spans=spans(sorted(frames - set(report["rendered"]))))
    if "staging" not in truth:
        for effect in truth["effects"]:
            effect["detail"] = FADING_TORCH.get(effect["kind"], effect["detail"])
    truth["credits"] = CREDITS
    # The sample count is the cap the frames were rendered with; sampling is adaptive below it.
    counts = sorted(n for n in samples if n)
    sampling = f", {' and '.join(map(str, counts))} samples" if counts and None not in samples else ""
    truth["renderer"] = f"Blender 5.3 Cycles{sampling} with OptiX denoising, half-frame motion blur; developed by camera_looks.py"
    if historic_cameras == len(truth["cameras"]) and archived:
        truth["renderer"] = archived[1]["renderer"]
    extra = HERE / "build" / "takes" / f"{take}.twin.json"
    if extra.exists():
        truth["twin"] = json.loads(extra.read_text())
    scene_path = out / "scene.json"
    render_files.write_text(scene_path, json.dumps(truth, separators=(",", ":")) + "\n")
    print("SCENE", scene_path, scene_path.stat().st_size, "bytes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("take")
    parser.add_argument("--cameras", default="", help="comma-separated ids; all when omitted")
    parser.add_argument("--frames", default="", help="develop these film frames to JPEGs instead of encoding")
    parser.add_argument("--preview", default="", help="folder for those JPEGs")
    parser.add_argument("--scene", action="store_true", help="only write scene.json from films already encoded")
    parser.add_argument("--crf", type=int, default=33, help="x264 quality; consumer cameras stream at low bitrates")
    parser.add_argument("--workers", type=int, default=6, help="processes that read and prepare frames")
    parser.add_argument("--out", default="", help="write films here instead of public/watch/<take>")
    parser.add_argument("--root", default="", help="folder holding <camera>/f####.exr, if not the take's own")
    args = parser.parse_args()
    if args.scene:
        write_scene(args.take, args.out or None)
        return
    frames = []
    for part in filter(None, args.frames.split(",")):
        a, _, b = part.partition("-")
        frames.extend(range(int(a), int(b or a) + 1))
    cameras = [c for c in args.cameras.split(",") if c]
    run(args.take, cameras, frames, args.preview, args.root or None, args.out or None, args.crf, args.workers)
    if not cameras and not frames and not args.preview:
        write_scene(args.take, args.out or None)


if __name__ == "__main__":
    main()
