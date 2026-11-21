"""Produce the paired, retained porch recordings for the camera dropout exhibit.

Run from any directory with FSS_BIN_DIR pointing to fss-file and fss-event.
The destination must be new. Encoding and packet removal are offline exhibit authoring.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


PUBLIC = Path(__file__).resolve().parents[1] / "public"
SOURCE = PUBLIC / "night-media/delivery-porch.mp4"
FPS = 8
START_NS = 100_000_000_000  # A synthetic relative clock, not a wall-clock observation.
SCOPE = ["--root", "lab", "--site", "site:porch-delivery"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(out, work, bins):
    def run(*args):
        return subprocess.run(args, cwd=work, check=True, stdout=subprocess.PIPE).stdout

    def receipt(name, binary, *args):
        data = run(bins / binary, *args)
        (out / name).write_bytes(data)
        return data

    capture = PUBLIC / "night-media/capture.json"
    mesh = PUBLIC / "estate/mesh-receipt.json"
    scene = json.loads((PUBLIC / "watch/intrusion/scene.json").read_bytes())
    recorded = json.loads(capture.read_bytes())
    model = json.loads(mesh.read_bytes())
    view, = [c for c in recorded["captures"] if (c["caseId"], c["camera"]) == ("delivery", "porch")]
    if (model["authoringBlendSha256"] != scene["source_blend_sha256"]
            or digest(PUBLIC / "estate/estate.glb") != model["packedGlbSha256"]
            or model["packedGlbSha256"] != recorded["inputs"]["/estate/estate.glb"]["sha256"]
            or view["videoSha256"] != digest(SOURCE)
            or (view["fps"], view["frames"], view["seconds"]) != (24, 192, 8)):
        raise ValueError("Delivery source does not match the published take or the current house")
    for src, dest in [(SOURCE, "source.mp4"), (capture, "capture.json"), (mesh, "mesh-receipt.json")]:
        shutil.copyfile(src, out / dest)

    # Each independently decodable packet is a specific third source frame.
    run("ffmpeg", "-v", "error", "-n", "-i", SOURCE, "-vf",
        "select=not(mod(n\\,3)),setpts=N/(8*TB),scale=640:360", "-r", str(FPS),
        "-c:v", "libx264", "-preset", "fast", "-crf", "17", "-g", "1", "-bf", "0",
        "-pix_fmt", "yuv420p", "-threads", "1", "-fflags", "+bitexact", "-flags:v", "+bitexact",
        "-map_metadata", "-1", out / "complete.mkv")
    # Copy surviving compressed packets with their original timestamps. No filler or retiming.
    run("ffmpeg", "-v", "error", "-n", "-i", out / "complete.mkv", "-map", "0:v:0",
        "-c:v", "copy", "-bsf:v", "noise=drop='between(n,24,39)'", "-fflags", "+bitexact",
        "-map_metadata", "-1", out / "dropout.mkv")

    for name in ("complete", "dropout"):
        movie = out / (name + ".mkv")
        # Stable input name in each native command and result, independent of the output location.
        shutil.copyfile(movie, work / movie.name)
        imported = receipt(name + "-import.txt", "fss-file", "import", *SCOPE,
                           "--input", movie.name, "--sensor", "sensor:porch", "--stream", "stream:delivery",
                           "--media-format", "mkvavc", "--receive-time-ns", str(START_NS + 10_000_000_000),
                           "--capture-start-ns", str(START_NS), "--capture-uncertainty-ns", "1000000",
                           "--assumed-fps", str(FPS))
        fields = dict(line.split("=", 1) for line in imported.decode().splitlines())
        if fields["verified_source_sha256"] != "sha256:" + digest(movie):
            raise ValueError("Native input digest differs from the recorded source")
        imported_id = fields["import_identity"]
        receipt(name + "-movie.txt", "fss-file", "select-movie", *SCOPE, "--import-id", imported_id,
                "--start-movie-tick", "0", "--end-movie-tick", "8000000000")
        frames = int(fields["segment_count"])
        # The first receipt covers the whole movie in a single watch. Keep the existing
        # recovery-only receipt addressable for readers of the original exhibit.
        windows = [(0, frames)]
        if name == "dropout":
            windows.append((24, frames - 24))
        for start, count in windows:
            args = ["watch", *SCOPE, "--import-id", imported_id, "--interpretation", "ycbcr",
                    "--zone", "porch:0,0,640,360", "--first-segment", str(start), "--segment-count", str(count)]
            preview = json.loads(run(bins / "fss-event", *args))
            receipt(f"{name}-watch-{start}.json", "fss-event", *args, "--retain-coverage",
                    preview["coverage"]["approval_digest"])
        run("ffmpeg", "-v", "error", "-n", "-i", movie, "-vf",
            f"scale=512:288,tile=8x{frames // 8}:nb_frames={frames}", "-frames:v", "1",
            "-threads", "1", "-c:v", "libwebp", "-quality", "88", out / (name + ".webp"))
    manifest = {
        "schema": "fss.website.delivery_dropout.v1", "fps": FPS, "sourceFps": view["fps"],
        "seconds": view["seconds"], "epochNs": START_NS, "model": model["authoringBlendSha256"],
        "files": {f.name: digest(f) for f in sorted(out.iterdir()) if f.is_file()},
    }
    (out / "replay.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    dest = args.destination.resolve()
    if dest.exists():
        parser.error("Choose a new destination; preserve existing evidence.")
    bins = Path(os.environ["FSS_BIN_DIR"]).resolve()
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        root = Path(tmp)
        stage = root / "public"
        stage.mkdir()
        build(stage, root, bins)
        subprocess.run(["node", Path(__file__).with_name("check-delivery-dropout.mjs"), stage,
                        PUBLIC / "watch/intrusion/scene.json"], check=True)
        stage.rename(dest)
