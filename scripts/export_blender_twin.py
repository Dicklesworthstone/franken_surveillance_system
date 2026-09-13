#!/usr/bin/env python3
"""Owner-run, read-only Blender exporter. Not invoked by the FSS runtime.

Run Blender with --background --disable-autoexec scene.blend --python this_file
-- --policy policy.json --output new.fsstwin. See docs/TWIN_IMPORT_REFERENCE.md.
Every evaluated mesh needs an explicit physical/exclude policy; no name heuristics.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from twin_interchange import encode_twin, publish_new, require


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_policy(path):
    with path.open("rb") as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    require(len(raw) <= 4 * 1024 * 1024, "policy exceeds 4 MiB")
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate policy key")
            out[key] = value
        return out
    policy = json.loads(raw, object_pairs_hook=pairs)
    require(set(policy) == {"schema", "source_sha256", "scene", "view_layer", "frame",
                            "epoch", "scale", "geometry_error", "objects"}, "policy fields")
    require(policy["schema"] == "fss.blender-export-policy/1", "policy schema")
    require(type(policy["frame"]) is int, "frame must be integer")
    require(isinstance(policy["objects"], dict) and len(policy["objects"]) <= 65536, "object policy")
    for key, row in policy["objects"].items():
        require(isinstance(key, str) and isinstance(row, dict), "policy entry")
        if row.get("role") == "exclude":
            require(set(row) == {"role", "reason"} and isinstance(row["reason"], str)
                    and row["reason"].strip(), "explicit exclusion reason required")
        else:
            require(set(row) == {"role", "feature", "surface", "support", "opaque"}
                    and row["role"] == "physical", "physical policy fields")
    return policy, hashlib.sha256(raw).hexdigest()


def export_scene(bpy, policy, policy_digest):
    require(bpy.data.filepath and not bpy.data.is_dirty, "open a saved, unmodified source")
    source = Path(bpy.data.filepath).resolve()
    require(sha(source) == policy["source_sha256"], "source hash mismatch")
    scene = bpy.data.scenes.get(policy["scene"])
    require(scene is not None and bpy.context.window is not None, "scene/window unavailable")
    layer = scene.view_layers.get(policy["view_layer"])
    require(layer is not None, "view layer missing")
    bpy.context.window.scene = scene
    bpy.context.window.view_layer = layer
    scene.frame_set(policy["frame"])
    graph = bpy.context.evaluated_depsgraph_get()
    features, objects, vertices, triangles, seen, source_ids = {}, [], [], [], set(), {}
    used_policy = set()
    for instance in graph.object_instances:
        obj = instance.object
        if obj.type != "MESH":
            continue
        original = obj.original
        stable = original.get("hhm_object_id")
        key = stable if stable else "name:" + original.name
        require(key in policy["objects"], "unclassified evaluated mesh; add an explicit policy")
        row = policy["objects"][key]
        used_policy.add(key)
        if row["role"] == "exclude":
            continue
        require(isinstance(stable, str) and stable and not stable.startswith("name:"), "physical mesh needs stable object ID")
        pointer = original.as_pointer()
        require(stable not in source_ids or source_ids[stable] == pointer, "duplicate source object ID")
        source_ids[stable] = pointer
        require(original.get("hhm_feature_id") == row["feature"], "feature identity differs from scene")
        identity = stable
        if instance.is_instance:
            parent = instance.parent.original if instance.parent is not None else None
            parent_id = parent.get("hhm_object_id") if parent else None
            require(isinstance(parent_id, str) and parent_id, "instance requires stable instancer ID")
            key_bytes = json.dumps([stable, parent_id, list(instance.persistent_id)], separators=(",", ":")).encode()
            identity = "instance:" + hashlib.sha256(key_bytes).hexdigest()
        require(identity not in seen, "duplicate evaluated instance")
        seen.add(identity)
        previous = features.get(row["feature"])
        require(previous is None or previous == row["surface"], "feature surface conflict")
        features[row["feature"]] = row["surface"]
        mesh = obj.to_mesh(preserve_all_data_layers=False, depsgraph=graph)
        try:
            require(mesh is not None, "evaluated mesh unavailable")
            mesh.calc_loop_triangles()
            require(len(mesh.loop_triangles) > 0, "physical object has no surface triangles")
            require(len(vertices) + len(mesh.vertices) <= 262144 and
                    len(triangles) + len(mesh.loop_triangles) <= 524288, "geometry budget")
            matrix = instance.matrix_world.copy()
            determinant = matrix.to_3x3().determinant()
            require(abs(determinant) > 1e-15, "singular instance transform")
            offset = len(vertices)
            vertices.extend([list(matrix @ vertex.co) for vertex in mesh.vertices])
            for triangle in mesh.loop_triangles:
                a, b, c = [offset + i for i in triangle.vertices]
                if determinant < 0:
                    b, c = c, b
                triangles.append([a, b, c, identity])
        finally:
            obj.to_mesh_clear()
        objects.append(dict(id=identity, feature=row["feature"], support=row["support"], opaque=row["opaque"]))
    require(all(key in used_policy for key, row in policy["objects"].items()
                if row["role"] == "physical"), "a requested physical object is absent from this evaluation")
    require(sha(source) == policy["source_sha256"], "source changed during export")
    scope = json.dumps({"scene": scene.name, "layer": layer.name, "frame": policy["frame"],
                        "policy_sha256": policy_digest, "axes": "RH_Z_UP", "evaluation": "VIEW_LAYER"},
                       ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return encode_twin(source_sha256=policy["source_sha256"], scope=scope, epoch=policy["epoch"],
                       scale=policy["scale"], geometry_error=policy["geometry_error"],
                       features=[dict(id=k, surface=v) for k, v in features.items()],
                       objects=objects, vertices=vertices, triangles=triangles)


def main():
    import bpy
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(sys.argv[sys.argv.index("--")+1:])
    policy, policy_digest = load_policy(args.policy)
    data = export_scene(bpy, policy, policy_digest)
    publish_new(args.output, data)
    print(json.dumps({"status": "EXPORTED_NOT_QUALIFIED", "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "source_modified": False}))


if __name__ == "__main__":
    main()
