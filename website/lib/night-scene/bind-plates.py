"""Bind photos rendered before mesh packing to the exact same exported source generation."""

import hashlib
import json
from pathlib import Path
import sys

source, public = map(Path, sys.argv[1:])
photo = json.loads((source / "unbound-preview.json").read_text())
mesh = json.loads((public / "estate/mesh-receipt.json").read_text())
plan_path = public / "estate/estate.json"
plan = json.loads(plan_path.read_text())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


if (
    photo["blendSha256"] != mesh["authoringBlendSha256"]
    or photo["planSha256"] != sha(plan_path)
    or mesh["packedGlbSha256"] != sha(public / "estate/estate.glb")
):
    raise ValueError(
        "The source scene, mesh or camera plan differs between the supplied captures"
    )
photo["glbSha256"] = mesh["packedGlbSha256"]
views = {c["id"]: c for c in [plan["overview"], *plan["cameras"]]}
expected = {
    "overview",
    *(camera for case in plan["incidents"] for camera in case["cameras"]),
}
if set(photo["views"]) != expected:
    raise ValueError("Missing photographic lens")
for name, receipt in photo["views"].items():
    view, path = views[name], source / (name + ".jpg")
    if (
        receipt["eye"] != view["position"]
        or receipt["target"] != view["look_at"]
        or receipt["verticalFovDegrees"] != view["vfov"]
        or receipt["sha256"] != sha(path)
        or receipt["url"] != f"/night-media/plates/{name}.jpg"
    ):
        raise ValueError("Invalid photographic projection " + name)
directory = public / "night-media/plates"
directory.mkdir(parents=True, exist_ok=True)
for name, view in photo["views"].items():
    path = directory / (name + ".jpg")
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes((source / path.name).read_bytes())
    if sha(tmp) != view["sha256"]:
        raise ValueError("Source changed during publication " + name)
    tmp.replace(path)
temporary_index = directory / "index.tmp"
temporary_index.write_text(json.dumps(photo, indent=2) + "\n")
temporary_index.replace(directory / "index.json")
