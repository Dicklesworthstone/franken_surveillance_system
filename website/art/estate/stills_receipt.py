"""Write public/estate/stills.json: one row per rendered still, bound to its source.

    python3 -B website/art/estate/stills_receipt.py <path to the frozen .blend receipt>
"""
import hashlib
import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
PUBLIC = HERE.parent.parent / "public" / "estate"


def jpeg_size(data):
    """Width and height from a JPEG's start-of-frame marker."""
    i = 2
    while i < len(data):
        marker, length = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            height, width = struct.unpack(">HH", data[i + 5:i + 9])
            return width, height
        i += 2 + length
    raise ValueError("no frame header")


source = json.loads(pathlib.Path(sys.argv[1]).read_text())
lenses = {name[4:] for name in source["cameras"] if name.startswith("cam_")}
rows = []
for path in [PUBLIC / "hero.jpg", *sorted((PUBLIC / "stills").glob("*.jpg"))]:
    data = path.read_bytes()
    width, height = jpeg_size(data)
    view = path.stem
    rows.append({
        "path": "/estate/" + str(path.relative_to(PUBLIC)),
        "camera": ("cam_" if view in lenses else "view_") + view,
        "width": width,
        "height": height,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    })
out = PUBLIC / "stills.json"
out.write_text(json.dumps({
    "schema": "fss.website.estate_stills.v1",
    "source_blend": source["file"],
    "source_blend_sha256": source["sha256"],
    "renderer": "Blender " + source["blender"] + " Cycles",
    "view_transform": source["render"]["view_transform"],
    "look": source["render"]["look"],
    "exposure": round(source["render"]["exposure"], 3),
    "stills": rows,
}, indent=2) + "\n")
print("wrote", out, len(rows), "stills")
