"""Measure the three generated films with local FSS binaries and the repository's pinned model."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

WEB = Path(__file__).resolve().parents[1]
MODEL = WEB.parent / "models/yolox-nano/yolox_nano.fmpk"
PIN = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74"
FILMS = WEB / "public/films"
OUT = WEB / "public/evidence"
BINS = Path(os.environ.get("FSS_BIN_DIR", WEB.parent / "target/debug")).resolve()

def run(args, cwd):
    return subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, text=True).stdout

def write(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")

def main():
    OUT.mkdir(exist_ok=True)
    if "sha256:" + hashlib.sha256(MODEL.read_bytes()).hexdigest() != PIN:
        raise ValueError("detector package differs from the reviewed digest")
    visibility = json.loads((FILMS / "visibility.json").read_text())
    summary = {}
    for case, camera in [("delivery", "porch"), ("wildlife", "garden"), ("visitor", "drive")]:
        with tempfile.TemporaryDirectory(prefix="fss-showcase-") as directory:
            tmp = Path(directory)
            shutil.copyfile(MODEL, tmp / "model.fmpk")
            frames = OUT / (case + ".mjpeg")
            run(["ffmpeg", "-v", "error", "-y", "-i", FILMS / (case + ".mp4"), "-vf", "fps=4,scale=160:90",
                 "-c:v", "mjpeg", "-q:v", "4", "-pix_fmt", "yuvj420p", "-threads", "1", "-f", "mjpeg", frames], tmp)
            shutil.copyfile(frames, tmp / "camera.mjpeg")
            scope = ["--root", "deployment", "--site", "site:juniper-demo"]
            imported = run([BINS / "fss-file", "import", *scope, "--input", "camera.mjpeg",
                "--sensor", "sensor:" + camera, "--stream", "stream:" + case, "--media-format", "mjpeg",
                "--receive-time-ns", "1700000020000000000", "--capture-start-ns", "1700000000000000000",
                "--capture-uncertainty-ns", "1000000", "--assumed-fps", "4"], tmp)
            identity = next(row.split("=",1)[1] for row in imported.splitlines() if row.startswith("import_identity="))
            report = json.loads(run([BINS / "fss-event", "watch", *scope, "--import-id", identity,
                "--interpretation", "ycbcr", "--zone", "image:0,0,160,90", "--detector-package", "model.fmpk",
                "--detector-digest", PIN, "--detector-max-inferences", "2"], tmp))
            assert report["frames_decoded"] == 48 and report["candidate_count"] == len(report["candidates"])
            write(case + ".json", report)
            summary[case] = {"candidates": report["candidate_count"], "frames": report["frames_decoded"],
                "entries": [{"time":row["entry_segment"]/4, "track":row["track_id"], "kind":row["event_kind"]}
                           for row in report["candidates"]], "visibility": visibility[case]}
            print(case, report["candidate_count"], report["analysis_digest"], flush=True)
    write("index.json", summary)

if __name__ == "__main__":
    main()
