"""Freeze the built scene as one self-contained, read-only generation.

    blender -b website/art/estate/build/estate.blend -P website/art/estate/freeze.py

Packs every image into the file, saves it under build/release/ named by its
own SHA-256, and writes a receipt beside it. Films, plates and exports for a
release should all come from one frozen file.
"""
import datetime
import hashlib
import json
import os
import pathlib

import bpy

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "build" / "release"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


OUT.mkdir(parents=True, exist_ok=True)
bpy.ops.file.pack_all()
candidate = OUT / "candidate.blend"
bpy.ops.wm.save_as_mainfile(filepath=str(candidate), copy=True, compress=True)
digest = sha256(candidate)
final = OUT / f"alder-house-{digest[:12]}.blend"
os.replace(candidate, final)
os.chmod(final, 0o444)
scene = bpy.context.scene
receipt = {
    "schema": "fss.website.estate_source.v1",
    "name": "Alder House",
    "file": final.name,
    "sha256": digest,
    "bytes": final.stat().st_size,
    "blender": bpy.app.version_string,
    "frozen_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "plan_sha256": sha256(HERE / "plan.py"),
    "assets_lock_sha256": sha256(HERE / "assets.lock.json"),
    "render": {
        "engine": scene.render.engine,
        "view_transform": scene.view_settings.view_transform,
        "look": scene.view_settings.look,
        "exposure": scene.view_settings.exposure,
        "samples": scene.cycles.samples,
    },
    "cameras": sorted(o.name for o in bpy.data.objects if o.type == "CAMERA"),
    "objects": len(bpy.data.objects),
}
(OUT / (final.stem + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
print("FROZEN", final, digest)
