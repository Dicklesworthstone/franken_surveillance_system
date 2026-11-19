"""Pack a single-buffer Blender GLB and publish its external textures before the geometry.

python3 scripts/pack-estate.py /path/to/raw.glb public/estate
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import file_digest, sha256
from io import BytesIO
import json
from pathlib import Path
import re
import struct
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import unquote

from PIL import Image

WEB = Path(__file__).resolve().parents[1]


def texture_encodings(source, normal, size):
    with Image.open(BytesIO(source)) as bitmap:
        alpha = (
            "A" in bitmap.getbands() and bitmap.getchannel("A").getextrema()[0] < 255
        )
        pic = bitmap.convert("RGBA" if alpha else "RGB")
    limit = min(512, size) if normal else size
    def encode(limit):
        pic.thumbnail((limit, limit), Image.Resampling.LANCZOS)
        output = BytesIO()
        pic.save(output, format="WEBP", quality=91 if normal else 85, method=4)
        return output.getvalue()

    full = encode(limit)
    compact_size = min(limit, 256 if normal else 512)
    compact = encode(compact_size) if max(pic.size) > compact_size else full
    return full, compact


def transform_view_refs(item, callback):
    if isinstance(item, list):
        for value in item:
            transform_view_refs(value, callback)
    elif isinstance(item, dict):
        for key, value in item.items():
            if key == "bufferView" and isinstance(value, int):
                item[key] = callback(value)
            else:
                transform_view_refs(value, callback)


def source_parts(path):
    data = path.read_bytes()
    magic, version, total, js_size, json_tag = struct.unpack_from("<4s4I", data)
    if (magic, version, total, json_tag) != (b"glTF", 2, len(data), 0x4E4F534A):
        raise ValueError("Expected an original glTF 2 binary")
    doc = json.loads(data[20 : 20 + js_size])
    offset = 20 + js_size
    _, bin_tag = struct.unpack_from("<II", data, offset)
    if bin_tag != 0x004E4942 or len(doc["buffers"]) != 1:
        raise ValueError("The source must contain exactly one binary buffer")
    if any("meshopt_compression" in ext for ext in doc.get("extensionsUsed", [])):
        raise ValueError("Supply the Blender source export before mesh optimization")
    return doc, memoryview(data)[offset + 8 :]


def extract_textures(doc, binary, stage, source, size):
    directory = stage / "textures"
    directory.mkdir()
    normals = {
        doc["textures"][m["normalTexture"]["index"]]["source"]
        for m in doc["materials"]
        if "normalTexture" in m
    }
    for material in doc["materials"]:
        # The Cycles asset uses Fresnel/transparent closures at these windows.
        if material.get("name", "").split(".")[0] in ("glass", "lantern_glass"):
            material.update(alphaMode="BLEND", doubleSided=True)
            material["pbrMetallicRoughness"] = {
                "baseColorFactor": [0.52, 0.67, 0.77, 0.16],
                "metallicFactor": 0.1,
                "roughnessFactor": 0.17,
            }
    def convert(item):
        number, image = item
        if "bufferView" in image:
            view = doc["bufferViews"][image["bufferView"]]
            begin = view.get("byteOffset", 0)
            raw = binary[begin : begin + view["byteLength"]]
        else:
            target = (source.parent / unquote(image["uri"])).resolve()
            if not target.is_relative_to(source.parent.resolve()):
                raise ValueError("An exterior texture points outside the source bundle")
            raw = target.read_bytes()
        return texture_encodings(raw, number in normals, size)

    discarded = set()
    variants = {}
    images = doc.get("images", [])
    with ThreadPoolExecutor(max_workers=4) as pool:
        for image, pair in zip(images, pool.map(convert, enumerate(images))):
            names = []
            for encoded in pair:
                name = sha256(encoded).hexdigest()[:22] + ".webp"
                path = directory / name
                if not path.exists():
                    path.write_bytes(encoded)
                names.append(name)
            full, compact = names
            variants["/estate/textures/" + full] = "/estate/textures/" + compact
            if "bufferView" in image:
                discarded.add(image.pop("bufferView"))
            image["uri"] = "textures/" + full
            image.pop("mimeType", None)
    for texture in doc.get("textures", []):
        texture.setdefault("extensions", {})["EXT_texture_webp"] = {
            "source": texture.pop("source")
        }
    if doc.get("textures"):
        for key in ("extensionsUsed", "extensionsRequired"):
            if "EXT_texture_webp" not in doc.setdefault(key, []):
                doc[key].append("EXT_texture_webp")
    return discarded, variants


def write_geometry(doc, binary, discarded, path):
    used = set()

    def retain(index):
        used.add(index)
        return index

    transform_view_refs(doc, retain)
    remap, views, output = {}, [], bytearray()
    for index, view in enumerate(doc["bufferViews"]):
        if index in discarded and index not in used:
            continue
        begin = view.get("byteOffset", 0)
        output.extend(bytes(-len(output) % 4))
        remap[index] = len(views)
        views.append({**view, "byteOffset": len(output)})
        output.extend(binary[begin : begin + view["byteLength"]])
    doc["bufferViews"] = views
    transform_view_refs(doc, remap.__getitem__)
    doc["buffers"][0]["byteLength"] = len(output)
    output.extend(bytes(-len(output) % 4))
    text = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode()
    text += b" " * (-len(text) % 4)
    with path.open("wb") as stream:
        stream.write(
            struct.pack(
                "<4s4I", b"glTF", 2, 28 + len(text) + len(output), len(text), 0x4E4F534A
            )
        )
        stream.write(text)
        stream.write(struct.pack("<II", len(output), 0x004E4942))
        stream.write(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--size", type=int, default=1024)
    args = parser.parse_args()
    receipt_path = args.source.with_suffix(".receipt.json")
    origin = None
    if receipt_path.is_file():
        origin = json.loads(receipt_path.read_text())
        with args.source.open("rb") as stream:
            if file_digest(stream, "sha256").hexdigest() != origin["rawGlbSha256"]:
                raise ValueError(
                    "Raw geometry does not match the Blender export receipt"
                )
        if not re.fullmatch("[0-9a-f]{64}", origin["authoringBlendSha256"]):
            raise ValueError("Invalid source scene identity in the export receipt")
    doc, binary = source_parts(args.source)
    args.destination.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=args.destination.parent, prefix=".packing-") as working:
        stage = Path(working)
        discarded, variants = extract_textures(doc, binary, stage, args.source, args.size)
        original, final = stage / "uncompressed.glb", stage / "estate.glb"
        write_geometry(doc, binary, discarded, original)
        subprocess.run(
            [
                WEB / "node_modules/.bin/gltfpack",
                "-i",
                original,
                "-o",
                final,
                "-cc",
                "-kn",
                "-tr",
                "-vpf",
            ],
            check=True,
        )
        if final.stat().st_size > 25 * 1024 * 1024:
            raise ValueError(
                "Packed estate exceeds the Cloudflare single-asset size limit"
            )
        textures = args.destination / "textures"
        textures.mkdir(exist_ok=True)
        files = list((stage / "textures").iterdir())
        total = sum(file.stat().st_size for file in files)
        for file in files:
            file.replace(textures / file.name)
        published = args.destination / "estate.glb"
        final.replace(published)
        if origin:
            receipt = {
                "schema": "fss.website.estate_mesh_receipt.v1",
                "authoringBlendSha256": origin["authoringBlendSha256"],
                "rawGlbSha256": origin["rawGlbSha256"],
                "packedGlbSha256": sha256(published.read_bytes()).hexdigest(),
                "textures": len(files),
                "textureBytes": total,
                "compactTextures": variants,
            }
            proof = stage / "mesh-receipt.json"
            proof.write_text(json.dumps(receipt, indent=2) + "\n")
            proof.replace(args.destination / proof.name)
    print(
        f"Packed {len(doc['meshes'])} unique meshes and {len(files)} textures ({total:,} texture bytes)"
    )


if __name__ == "__main__":
    main()
