"""Export the frozen authoring scene as a browser mesh derivative.

blender -b approved.blend -P export-estate.py -- /staging/estate.glb
The source scene stays read-only. Collection instances become shared glTF meshes.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from tempfile import gettempdir

import bpy
import numpy as np


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


destination = Path(sys.argv[sys.argv.index("--") + 1]).resolve()
destination.parent.mkdir(parents=True, exist_ok=True)
source = Path(bpy.data.filepath)
source_digest = sha(source)
original = bpy.context.scene
deps = bpy.context.evaluated_depsgraph_get()
placements = []
omitted_blades = 0
for entry in deps.object_instances:
    obj = entry.object.original
    if obj.type != "MESH" or obj.hide_render:
        continue
    owner = entry.parent.original if entry.is_instance else obj
    if entry.is_instance and owner.name == "lawn_blades":
        omitted_blades += 1
        continue
    planting = any(col.name == "Planting" for col in owner.users_collection)
    placements.append((owner.name, obj, entry.matrix_world.copy(), planting))
print("Scene source", source_digest, "instances", len(placements), flush=True)

# Bound raster decoding before the glTF exporter reads a panorama or a 4K PBR set.
texture_cache = destination.parent / "texture-cache"
texture_cache.mkdir(exist_ok=True)
shared_images = Path(gettempdir()) / f"fss-estate-images-{os.getuid()}"
shared_images.mkdir(mode=0o700, exist_ok=True)
source_images = {}
materials = {
    m for _, obj, _, _ in placements for m in obj.data.materials if m and m.node_tree
}
images = set()


def collect_images(tree):
    for node in tree.nodes:
        if node.type == "TEX_IMAGE" and node.image:
            images.add(node.image)
        if node.type == "GROUP" and node.node_tree:
            collect_images(node.node_tree)


for material in materials:
    collect_images(material.node_tree)
for im in sorted(images, key=lambda image: image.name):
    path = Path(bpy.path.abspath(im.filepath))
    if path.suffix.lower() not in (
        ".png",
        ".jpg",
        ".jpeg",
        ".tga",
        ".tif",
    ):
        continue
    if im.packed_file:
        packed = im.packed_file.data
        digest = hashlib.sha256(packed).hexdigest()
        path = shared_images / (digest + path.suffix.lower())
        if not path.exists():
            path.write_bytes(packed)
    elif path.is_file():
        digest = sha(path)
    else:
        raise ValueError(f"Unavailable source texture {im.name}")
    if path not in source_images:
        target = shared_images / (
            "1024-"
            + digest
            + (".jpg" if path.suffix.lower() in (".jpeg", ".jpg") else ".png")
        )
        if not target.exists():
            staging = target.with_stem(target.stem + f".{os.getpid()}")
            subprocess.run(
                [
                    "vipsthumbnail",
                    str(path),
                    "--size",
                    "1024x1024>",
                    "-o",
                    str(staging),
                ],
                check=True,
            )
            staging.replace(target)
        source_images[path] = target
    label = im.name
    replacement = bpy.data.images.load(str(source_images[path]), check_existing=False)
    replacement.colorspace_settings.name = im.colorspace_settings.name
    replacement.alpha_mode = im.alpha_mode
    im.name = "source " + label
    replacement.name = label
    im.user_remap(replacement)
print("Browser source textures", len(source_images), flush=True)


def bsdf(mat):
    nodes = mat.node_tree.nodes
    output = next(n for n in nodes if n.type == "OUTPUT_MATERIAL")
    shader = nodes.new("ShaderNodeBsdfPrincipled")
    mat.node_tree.links.new(shader.outputs[0], output.inputs["Surface"])
    return shader


for mat in sorted(materials, key=lambda material: material.name):
    nodes = mat.node_tree.nodes
    clear = next((n for n in nodes if n.type == "BSDF_TRANSPARENT"), None)
    images = [n for n in nodes if n.type == "TEX_IMAGE" and n.image]
    alpha = next((n for n in images if "_alpha." in n.image.name.lower()), None)
    diffuse = next((n for n in images if "_diff." in n.image.name.lower()), None)
    if alpha and diffuse:
        shader = next((n for n in nodes if n.type == "BSDF_PRINCIPLED"), None) or bsdf(
            mat
        )
        output = next(n for n in nodes if n.type == "OUTPUT_MATERIAL")
        mat.node_tree.links.new(shader.outputs[0], output.inputs["Surface"])
        mat.node_tree.links.new(diffuse.outputs["Color"], shader.inputs["Base Color"])
        cutoff = nodes.new("ShaderNodeMath")
        cutoff.operation = "GREATER_THAN"
        cutoff.inputs[1].default_value = 0.4
        mat.node_tree.links.new(alpha.outputs["Color"], cutoff.inputs[0])
        mat.node_tree.links.new(cutoff.outputs[0], shader.inputs["Alpha"])
        mat.use_backface_culling = False
    elif clear and any(n.type == "FRESNEL" for n in nodes):
        shader = bsdf(mat)
        shader.inputs["Base Color"].default_value = clear.inputs["Color"].default_value
        shader.inputs["Roughness"].default_value = 0.16
        shader.inputs["Alpha"].default_value = 0.25
        mat.surface_render_method = "BLENDED"
    elif mat.name.startswith("interior_"):
        # Sample the authored rectilinear room projection into a single UV map.
        env = next(n for n in nodes if n.type == "TEX_ENVIRONMENT").image
        yaw = int(mat.name.rsplit("_", 2)[1])
        emit = next(n for n in nodes if n.type == "EMISSION")
        strength = emit.inputs["Strength"].default_value
        tint = (
            next(n for n in nodes if n.type == "MIX" and n.blend_type == "MULTIPLY")
            .inputs["B"]
            .default_value
        )
        target = texture_cache / (mat.name + ".png")
        if not target.exists():
            iw, ih = env.size
            buffer = np.empty(iw * ih * 4, dtype=np.float32)
            env.pixels.foreach_get(buffer)
            pixels = buffer.reshape(ih, iw, 4)
            w, h = 256, 160
            yy, xx = np.mgrid[0:h, 0:w]
            vx = (2 * (xx + 0.5) / w - 1) * math.tan(math.radians(37))
            vz = (2 * (yy + 0.5) / h - 1) * math.tan(math.radians(37)) * 0.62
            a = math.radians(yaw)
            vx, vy = math.cos(a) * vx - math.sin(a), math.sin(a) * vx + math.cos(a)
            u = (0.5 - np.arctan2(vy, vx) / (2 * math.pi)) % 1
            v = 0.5 + np.arctan2(vz, np.hypot(vx, vy)) / math.pi
            crop = pixels[
                np.minimum(ih - 1, (v * ih).astype(int)),
                np.minimum(iw - 1, (u * iw).astype(int)),
            ].copy()
            crop[:, :, :3] = np.minimum(2.5, crop[:, :, :3]) * np.array(tint[:3])
            crop[:, :, :3] /= 1 + crop[:, :, :3]
            crop[:, :, 3] = 1
            img = bpy.data.images.new(mat.name, w, h)
            img.pixels.foreach_set(crop.ravel())
            img.filepath_raw, img.file_format = str(target), "PNG"
            img.save()
            bpy.data.images.remove(img)
        tex = nodes.new("ShaderNodeTexImage")
        tex.image = bpy.data.images.load(str(target), check_existing=True)
        shader = bsdf(mat)
        shader.inputs["Base Color"].default_value = (0, 0, 0, 1)
        mat.node_tree.links.new(tex.outputs["Color"], shader.inputs["Emission Color"])
        shader.inputs["Emission Strength"].default_value = min(2.2, strength * 0.55)


def reduced_mesh(mesh, target):
    """Simplify by material, retaining source positions and corner texture coordinates."""
    mesh.calc_loop_triangles()
    tris = mesh.loop_triangles

    def floats(seq, key, cols):
        out = np.empty((len(seq), cols), dtype=np.float32)
        seq.foreach_get(key, out.ravel())
        return out

    def ints(seq, key, cols):
        out = np.empty((len(seq), cols), dtype=np.int32)
        seq.foreach_get(key, out.ravel())
        return out

    points = floats(mesh.vertices, "co", 3)
    source_tri = ints(tris, "vertices", 3)
    source_mat = ints(tris, "material_index", 1).ravel()
    source_loop = ints(tris, "loops", 3)
    uv_sets = {layer.name: floats(layer.uv, "vector", 2) for layer in mesh.uv_layers}
    loop_vertices = ints(mesh.loops, "vertex_index", 1).ravel()
    for attr in mesh.attributes:
        if (
            attr.name in uv_sets
            or not attr.name.lower().startswith("uv")
            or attr.data_type not in ("FLOAT2", "FLOAT_VECTOR")
        ):
            continue
        coords = floats(attr.data, "vector", 2 if attr.data_type == "FLOAT2" else 3)[
            :, :2
        ]
        if attr.domain == "POINT":
            coords = coords[loop_vertices]
        if len(coords) == len(mesh.loops):
            uv_sets[attr.name] = coords
    uv_name = (
        mesh.uv_layers.active.name
        if mesh.uv_layers.active
        else next(iter(uv_sets), None)
    )
    made_vertices, made_faces, made_mat, made_loops = [], [], [], []
    vertex_offset = 0
    for slot in np.unique(source_mat):
        mask = source_mat == slot
        corners = source_tri[mask].ravel()
        loops = source_loop[mask].ravel()
        texcoords = (
            uv_sets[uv_name][loops]
            if uv_name
            else np.zeros((len(corners), 2), np.float32)
        )
        keys = np.column_stack(
            (corners, *(uv[loops].view(np.int32) for uv in uv_sets.values()))
        )
        packed = keys.view(np.dtype((np.void, keys.shape[1] * 4))).ravel()
        _, first, inverse = np.unique(packed, return_index=True, return_inverse=True)
        pos = points[corners[first]]
        tex = texcoords[first]
        tri_index = inverse.astype("<u4")
        keep = min(
            len(tri_index),
            max(24, round(target * np.count_nonzero(mask) / len(tris))) * 3,
        )
        if keep < len(tri_index):
            intermediate = destination.parent / "_mesh.bin"
            result = destination.parent / "_mesh-reduced.bin"
            with intermediate.open("wb") as stream:
                np.asarray([len(pos), len(tri_index), keep], dtype="<u4").tofile(stream)
                pos.astype("<f4").tofile(stream)
                tex.astype("<f4").tofile(stream)
                tri_index.tofile(stream)
            subprocess.run(
                [
                    "node",
                    str(Path(__file__).with_name("simplify-estate.mjs")),
                    str(intermediate),
                    str(result),
                ],
                check=True,
            )
            tri_index = np.fromfile(result, dtype="<u4")
        if not len(tri_index):
            continue
        used, remap = np.unique(tri_index, return_inverse=True)
        made_vertices.append(pos[used])
        made_faces.append(remap.astype(np.int32) + vertex_offset)
        made_mat.append(np.full(len(tri_index) // 3, slot, np.int32))
        made_loops.append(loops[first[tri_index]])
        vertex_offset += len(used)
    positions = np.concatenate(made_vertices)
    indices = np.concatenate(made_faces)
    result = bpy.data.meshes.new(mesh.name + " browser")
    for mat in mesh.materials:
        result.materials.append(mat)
    result.vertices.add(len(positions))
    result.vertices.foreach_set("co", positions.ravel())
    result.loops.add(len(indices))
    result.loops.foreach_set("vertex_index", indices)
    faces = len(indices) // 3
    result.polygons.add(faces)
    result.polygons.foreach_set(
        "loop_start", np.arange(0, len(indices), 3, dtype=np.int32)
    )
    result.polygons.foreach_set("material_index", np.concatenate(made_mat))
    result.polygons.foreach_set("use_smooth", np.ones(faces, dtype=bool))
    result.update(calc_edges=True)
    retained_loops = np.concatenate(made_loops)
    for name, uv in uv_sets.items():
        out = result.uv_layers.new(name=name)
        out.uv.foreach_set("vector", uv[retained_loops].ravel())
    if uv_name:
        result.uv_layers.active = result.uv_layers[uv_name]
    result.validate()
    return result


# Flatten collection instances into a short table of shared real mesh prototypes.
# Parent empties retain the authored placement identities of lenses and props.
scene = bpy.data.scenes.new("Alder House")
bpy.context.window.scene = scene
scene["authoringBlendSha256"] = source_digest
cache, groups = {}, {}
reductions = []
for name, obj, matrix, planting in placements:
    if obj.data not in cache:
        mesh = obj.data
        tri = sum(len(p.vertices) - 2 for p in mesh.polygons)
        limit = 20000 if planting else 125000
        if tri > limit:
            print("Reducing", obj.name, tri, "to", limit, flush=True)
            mesh = reduced_mesh(mesh, limit)
            reductions.append((obj.name, tri, len(mesh.polygons)))
            print("Mesh derivative", reductions[-1], flush=True)
        cache[obj.data] = mesh
    group = groups.get(name)
    if group is None:
        group = bpy.data.objects.new(name + "_placement", None)
        scene.collection.objects.link(group)
        groups[name] = group
    placed = bpy.data.objects.new(obj.name + "_surface", cache[obj.data])
    scene.collection.objects.link(placed)
    placed.parent = group
    placed.matrix_world = matrix
settings = set(bpy.ops.export_scene.gltf.get_rna_type().properties.keys())
options = dict(
    filepath=str(destination),
    export_format="GLB",
    export_animations=False,
    export_gpu_instances=True,
    export_lights=False,
    export_cameras=False,
    export_texcoords=True,
    export_normals=True,
    export_yup=True,
    export_extras=True,
    export_morph=False,
    use_active_scene=True,
    export_draco_mesh_compression_enable=False,
)
print("Writing real geometry", len(cache), len(groups), flush=True)
result = bpy.ops.export_scene.gltf(
    **{k: v for k, v in options.items() if k in settings}
)
if (
    "FINISHED" not in result
    or not destination.is_file()
    or sha(source) != source_digest
):
    raise RuntimeError("Estate export failed or authoring source changed")
receipt = dict(
    schema="fss.estate.browser_mesh_export.v1",
    authoringBlendSha256=source_digest,
    rawGlbSha256=sha(destination),
    placedMeshes=len(placements),
    uniquePrototypes=len(cache),
    photographicGrassInstances=omitted_blades,
    decimatedPrototypes=reductions,
)
destination.with_suffix(".receipt.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print("RAW READY", destination, receipt["rawGlbSha256"], flush=True)
