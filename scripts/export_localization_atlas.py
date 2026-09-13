#!/usr/bin/env python3
"""Owner-run COLMAP text/reference-image -> FSATLAS1 producer, never an FSS runtime dependency."""
from __future__ import annotations
import argparse
from fractions import Fraction
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import struct
import sys

MAX_FILE = 32 * 1024 * 1024
DOMAIN = b'fss/fast9-oriented-brief256/reference/1;pixel-edge;moment-disk8;mean3;lcg1664525+1013904223-seed731;pair-square10;nearest-away'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).digest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def hashed(value):
    return sha(canonical(value)).hex()


def hashbytes(value):
    require(isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value), 'invalid SHA-256')
    result = bytes.fromhex(value)
    require(result != bytes(32), 'zero identity')
    return result


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and abs(value) <= 1e12, 'invalid finite number')
    return float(value)


def integer(value, minimum=0, maximum=2**64-1):
    require(type(value) is int and minimum <= value <= maximum, 'integer outside bounds')
    return value


def load_json(data):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('nonfinite JSON')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def read(path, maximum=MAX_FILE):
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, 'file exceeds bound')
    return data


def member(root, name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name and '\x00' not in name, 'invalid local member')
    p = PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts, 'member escapes source directory')
    resolved = (root / name).resolve()
    require(resolved.is_relative_to(root), 'symlink escapes source directory')
    return resolved


def bound(root, record, maximum=MAX_FILE):
    data = read(member(root, record['path']), maximum)
    require(sha(data) == hashbytes(record['sha256']), 'source file hash mismatch')
    return data


def fields(line):
    require(len(line) <= 1024*1024, 'model line exceeds bound')
    return line.split()


def data_lines(text):
    for line in text.splitlines():
        require(len(line) <= 1024*1024, 'model line exceeds bound')
        if line.strip() and not line.lstrip().startswith('#'):
            yield line


def rotation(q):
    require(len(q) == 4 and abs(sum(number(x)**2 for x in q)-1) <= 1e-6, 'nonunit camera quaternion')
    w, x, y, z = q
    return [[1-2*(y*y+z*z), 2*(x*y-z*w), 2*(x*z+y*w)],
            [2*(x*y+z*w), 1-2*(x*x+z*z), 2*(y*z-x*w)],
            [2*(x*z-y*w), 2*(y*z+x*w), 1-2*(x*x+y*y)]]


def dot(a, b):
    return sum(x*y for x, y in zip(a, b))


def mv(r, p):
    return [dot(row, p) for row in r]


def transpose(r):
    return [list(row) for row in zip(*r)]


def transform(recipe):
    scale = number(recipe['scale'])
    require(0 < scale <= 1e9, 'invalid map scale')
    r, t = recipe['rotation'], recipe['translation']
    require(len(r) == 3 and all(len(row) == 3 for row in r) and len(t) == 3, 'invalid map transform shape')
    r = [[number(x) for x in row] for row in r]
    t = [number(x) for x in t]
    for i in range(3):
        for j in range(3):
            require(abs(dot(r[i], r[j]) - (i == j)) < 1e-8, 'map rotation is not orthogonal')
    determinant = sum(r[0][i]*(r[1][(i+1)%3]*r[2][(i+2)%3]-r[1][(i+2)%3]*r[2][(i+1)%3]) for i in range(3))
    require(abs(determinant-1) < 1e-8, 'map transform contains a reflection')
    return scale, r, t


def parse_model(cameras_text, images_text, points_text):
    cameras, images, points = {}, {}, {}
    for line in data_lines(cameras_text):
        f = fields(line)
        require(4 <= len(f) <= 32, 'invalid camera row')
        cid, model, width, height = int(f[0]), f[1], int(f[2]), int(f[3])
        require(cid > 0 and cid not in cameras and 0 < width <= 65536 and 0 < height <= 65536, 'invalid camera identity or dimensions')
        params = [number(float(x)) for x in f[4:]]
        cameras[cid] = (model, width, height, params)
        require(len(cameras) <= 4096, 'too many cameras')
    observation_count = 0
    lines = iter(images_text.splitlines())
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        require(len(line) <= 1024*1024, 'image header exceeds bound')
        f = line.split(maxsplit=9)
        require(len(f) == 10, 'invalid image header')
        iid, cid = int(f[0]), int(f[8])
        require(iid > 0 and iid not in images and cid in cameras, 'invalid image/camera identity')
        q = [number(float(x)) for x in f[1:5]]
        t = [number(float(x)) for x in f[5:8]]
        r = rotation(q)
        observation_line = next(lines, None)
        while observation_line is not None and observation_line.lstrip().startswith('#'):
            observation_line = next(lines, None)
        require(observation_line is not None, 'missing image observation row')
        raw = fields(observation_line)
        require(len(raw) % 3 == 0 and len(raw) <= 3*65536, 'invalid observation row')
        observation_count += len(raw)//3
        require(observation_count <= 1000000, 'model observation budget exceeded')
        observations = [(number(float(raw[i])), number(float(raw[i+1])), int(raw[i+2])) for i in range(0, len(raw), 3)]
        require(all(p >= -1 for _, _, p in observations), 'invalid point reference')
        images[iid] = dict(camera=cid, name=f[9], rotation=r, translation=t, observations=observations)
        require(len(images) <= 4096, 'too many images')
    for line in data_lines(points_text):
        f = fields(line)
        require(len(f) >= 8 and (len(f)-8) % 2 == 0, 'invalid point row')
        pid = int(f[0]); integer(pid, 1)
        require(pid not in points, 'duplicate point ID')
        xyz = [number(float(x)) for x in f[1:4]]
        require(all(0 <= int(x) <= 255 for x in f[4:7]), 'invalid point RGB')
        error = number(float(f[7])); require(error >= 0, 'negative reprojection error')
        tracks = [(int(f[i]), int(f[i+1])) for i in range(8, len(f), 2)]
        require(len(tracks) <= 4096 and len(set(tracks)) == len(tracks), 'invalid point tracks')
        require(all(i > 0 and j >= 0 for i, j in tracks), 'invalid track index')
        points[pid] = dict(xyz=xyz, error_px=error, tracks=tracks)
        require(len(points) <= 100000, 'too many map points')
    return cameras, images, points


def gray(data):
    if data.startswith(b'P5'):
        pos = 2; values = []
        while len(values) < 3:
            while pos < len(data) and data[pos] in b' \t\r\n':
                pos += 1
            if pos < len(data) and data[pos] == 35:
                end = data.find(b'\n', pos); require(end >= 0, 'unterminated PGM comment'); pos = end+1; continue
            end = pos
            while end < len(data) and 48 <= data[end] <= 57:
                end += 1
            require(end > pos and end-pos <= 10, 'invalid PGM header')
            values.append(int(data[pos:end])); pos = end
        require(pos < len(data) and data[pos] in b' \t\r\n', 'missing PGM raster separator')
        pos += 2 if data[pos:pos+2] == b'\r\n' else 1
        width, height, maximum = values
        require(maximum == 255 and 0 < width <= 4096 and 0 < height <= 4096 and width*height <= 4194304, 'unsupported grayscale image')
        pixels = data[pos:]; require(len(pixels) == width*height, 'PGM raster length mismatch')
        return width, height, pixels
    require(data.startswith(b'\x89PNG\r\n\x1a\n'), 'only grayscale PNG or P5 PGM is admitted')
    from PIL import Image
    with Image.open(io.BytesIO(data)) as image:
        width, height = image.size
        require(image.mode == 'L' and 0 < width <= 4096 and 0 < height <= 4096 and width*height <= 4194304, 'PNG must already be bounded 8-bit grayscale')
        return width, height, image.tobytes()


def descriptor(pixels, width, x, y):
    def mean(dx, dy):
        return sum(pixels[(y+dy+yy)*width+x+dx+xx] for yy in (-1, 0, 1) for xx in (-1, 0, 1))
    mx = my = 0
    for dy in range(-8, 9):
        for dx in range(-8, 9):
            if dx*dx+dy*dy <= 64:
                value = mean(dx, dy); mx += dx*value; my += dy*value
    angle = math.atan2(my, mx); sine, cosine = math.sin(angle), math.cos(angle)
    def rounding(n):
        return math.floor(n+0.5) if n >= 0 else math.ceil(n-0.5)
    def sample(dx, dy):
        return mean(rounding(cosine*dx-sine*dy), rounding(sine*dx+cosine*dy))
    state = 731; words = [0]*4
    for bit in range(256):
        pair = []
        for _ in range(4):
            state = (state*1664525+1013904223) & 0xffffffff; pair.append(state % 21-10)
        if sample(*pair[:2]) < sample(*pair[2:]):
            words[bit//64] |= 1 << (bit % 64)
    return words


def twin_features(data, expected, source):
    require(sha(data) == hashbytes(expected) and data[:8] == b'FSSTWIN1' and len(data) >= 48, 'twin identity/header mismatch')
    require(struct.unpack_from('<Q', data, 8)[0] == len(data)-48 and sha(data[:-32]) == data[-32:], 'invalid twin checksum/length')
    require(data[16:48] == hashbytes(source), 'twin source-scene mismatch')
    offset = 48
    def text():
        nonlocal offset
        n = struct.unpack_from('<H', data, offset)[0]; offset += 2
        require(0 < n <= 2048 and offset+n <= len(data)-32, 'invalid twin text')
        value = data[offset:offset+n].decode('utf-8'); offset += n; return value
    text(); text(); offset += 25
    count = struct.unpack_from('<I', data, offset)[0]; offset += 16
    require(0 < count <= 65536, 'invalid twin feature count')
    result = {}
    for index in range(count):
        name = text(); require(name not in result, 'duplicate twin feature'); result[name] = index
        require(data[offset] <= 5, 'unsupported twin surface'); offset += 1
    return result


def pack_atlas(twin, points, views, bindings, provenance):
    p = struct.pack
    def f64(n):
        return p('<d', 0. if n == 0 else number(n))
    points = sorted(points, key=lambda x: x['id']); views = sorted(views, key=lambda x: x['id']); bindings = sorted(bindings)
    require(0 < len(points) <= 4096 and 0 < len(views) <= 64 and 0 < len(bindings) <= 32768, 'archive counts outside limits')
    semantic = b'fss/localization-atlas/reference/1\0' + twin + sha(DOMAIN) + p('<Q', len(points)); body = b''
    for point in points:
        common = b''.join(f64(x) for x in point['world']) + hashbytes(point['evidence']) + bytes([point['error'] is not None])
        if point['error'] is not None:
            common += b''.join(f64(x) for x in point['error'])
        body += p('<QQI', point['id'], point['group'], point['feature']) + common
        semantic += p('<QQQ', point['id'], point['group'], point['feature']) + common
    semantic += p('<Q', len(views))
    for view in views:
        hashes = b''.join(hashbytes(view[x]) for x in ('exposure', 'pixels', 'image_domain'))
        features = sorted(view['features'], key=lambda x: x['id'])
        body += p('<Q', view['id']) + hashes + p('<II', *view['dimensions']) + hashbytes(view['record']) + hashbytes(view['mask']) + p('<I', len(features))
        semantic += p('<Q', view['id']) + hashes + p('<QQQ', *view['dimensions'], len(features))
        for feature in features:
            record = p('<Q', feature['id']) + b''.join(f64(x) for x in feature['pixel']) + p('<QQQQ', *feature['descriptor'])
            body += record; semantic += record
    links = b''.join(p('<QQQ', *b) for b in bindings)
    semantic += p('<Q', len(bindings)) + links; body += links
    payload = twin + sha(DOMAIN) + sha(semantic) + provenance + p('<III', len(points), len(views), len(bindings)) + body
    output = b'FSATLAS1' + p('<Q', len(payload)) + payload
    require(len(output)+32 <= 8*1024*1024, 'archive exceeds byte limit')
    return output + sha(output)


def build(recipe_data, root):
    recipe = load_json(recipe_data)
    require(recipe['schema'] == 'fss.colmap-atlas-recipe/1', 'unsupported recipe')
    root = Path(root).resolve()
    twin = bound(root, recipe['twin'], 64*1024*1024)
    features = twin_features(twin, recipe['twin']['sha256'], recipe['source_scene_sha256'])
    model_bytes = {key: bound(root, recipe['model'][key]) for key in ('cameras', 'images', 'points3D')}
    cameras, images, points = parse_model(*(model_bytes[key].decode('utf-8') for key in ('cameras', 'images', 'points3D')))
    s, r, t = transform(recipe['map_to_property'])
    snap = number(recipe['maximum_reference_snap_px']); residual_limit = number(recipe['maximum_reprojection_px'])
    require(0 <= snap <= .75 and .001 <= residual_limit <= 128, 'invalid observation thresholds')
    require(0 < len(recipe['landmarks']) <= 4096 and 0 < len(recipe['references']) <= 64, 'invalid selected scope')
    map_root = hashed({key: sha(value).hex() for key, value in model_bytes.items()})
    landmarks = {}; positions = set(); groups = set()
    for key, assignment in recipe['landmarks'].items():
        pid = int(key); require(str(pid) == key and pid in points, 'unknown/noncanonical selected point')
        point = points[pid]; group = integer(assignment.get('physical_group', pid), 1)
        require(group not in groups, 'duplicate physical group'); groups.add(group)
        require(assignment['feature_id'] in features, 'unknown twin feature')
        world = [number(s*a+b) for a, b in zip(mv(r, point['xyz']), t)]
        require(tuple(world) not in positions, 'duplicate physical position'); positions.add(tuple(world))
        error = assignment['error']
        require(error is None or (isinstance(error, list) and len(error) == 3 and all(number(x) >= 0 for x in error)), 'invalid declared map error')
        require(len(point['tracks']) >= 2, 'selected point lacks multiview support')
        seen_images = set()
        for iid, index in point['tracks']:
            require(iid in images and index < len(images[iid]['observations']) and images[iid]['observations'][index][2] == pid, 'nonreciprocal map track')
            require(iid not in seen_images, 'point repeats an exposure'); seen_images.add(iid)
        evidence = hashed(dict(map_root=map_root, point_id=pid, point=point, map_to_property=recipe['map_to_property']))
        landmarks[pid] = dict(id=pid, group=group, feature=features[assignment['feature_id']], world=world, evidence=evidence, error=error)
    views, bindings, source_records, rejected, selected_ids, exposures = [], [], {}, [], set(), set()
    used = set(); descriptions = 0
    for ref in sorted(recipe['references'], key=lambda x: x['image_id']):
        iid = integer(ref['image_id'], 1); require(iid in images and iid not in selected_ids, 'duplicate/unknown reference image'); selected_ids.add(iid)
        require(ref['partition'] in ('mapping', 'development'), 'held-out imagery cannot become fitting evidence')
        require(ref['image_domain_kind'] == 'undistorted-pinhole-pixel-edge', 'unsupported image domain')
        image = images[iid]; require(ref['image_name'] == image['name'], 'reference name/model mismatch')
        model, width, height, params = cameras[image['camera']]
        require((model == 'PINHOLE' and len(params) == 4) or (model == 'SIMPLE_PINHOLE' and len(params) == 3), 'reference camera must be explicitly undistorted pinhole')
        fx, fy, cx, cy = params if model == 'PINHOLE' else [params[0], params[0], params[1], params[2]]
        require(fx > 0 and fy > 0, 'invalid focal length')
        raw = bound(root, ref['image'], 8*1024*1024); w, h, pixels = gray(raw)
        require((w, h) == (width, height), 'image/model dimensions mismatch')
        mask = bound(root, ref['allowed_mask'], 4194304)
        require(len(mask) == len(pixels) and all(x in (0, 1) for x in mask), 'invalid full allowed-pixel mask')
        source = ref['source']; hashbytes(source['sha256']); integer(source['stream'], 0, 2**32-1); integer(source['pts'], -(2**63), 2**63-1)
        require(len(source['time_base']) == 2, 'invalid source time base')
        for n in source['time_base']:
            integer(n, 1, 2**32-1)
        stamp = Fraction(source['pts']*source['time_base'][0], source['time_base'][1])
        exposure = hashed(dict(domain='fss/source-exposure/atlas-authoring/1', source_sha256=source['sha256'],
            stream=source['stream'], time_numerator=stamp.numerator, time_denominator=stamp.denominator))
        require(exposure not in exposures, 'reused reference exposure'); exposures.add(exposure)
        hashbytes(ref['image_domain_sha256'])
        candidates, decisions, seen = [], [], set()
        for index, (u, v, pid) in enumerate(image['observations']):
            if pid not in landmarks:
                continue
            require(pid not in seen and (iid, index) in points[pid]['tracks'], 'duplicate/nonreciprocal selected observation'); seen.add(pid)
            camera_point = [a+b for a, b in zip(mv(image['rotation'], points[pid]['xyz']), image['translation'])]
            x, y = math.floor(u), math.floor(v)
            offset = math.hypot(x+.5-u, y+.5-v)
            error = None; reason = None
            if not 0 <= u < w or not 0 <= v < h:
                reason = 'outside_image'
            elif camera_point[2] <= 1e-9:
                reason = 'behind_camera'
            else:
                error = math.hypot(fx*camera_point[0]/camera_point[2]+cx-u, fy*camera_point[1]/camera_point[2]+cy-v)
                if not math.isfinite(error) or error > residual_limit:
                    reason = 'reprojection_mismatch'
                elif offset > snap:
                    reason = 'sampling_offset_exceeds_declared_bound'
                elif x < 16 or y < 16 or x >= w-16 or y >= h-16:
                    reason = 'descriptor_border'
                elif any(0 in mask[yy*w+x-16:yy*w+x+17] for yy in range(y-16, y+17)):
                    reason = 'masked_footprint'
            decision = dict(image_feature=index+1, landmark=pid, observed_pixel=[u, v], sampled_pixel=[x+.5, y+.5], sampling_offset_px=offset, reprojection_px=error, rejection=reason)
            decisions.append(decision)
            if reason is None:
                candidates.append((error, pid, index, x, y, decision))
        tiles = {}; retained = []
        for candidate in sorted(candidates, key=lambda a: (a[0], a[1])):
            _, pid, index, x, y, decision = candidate
            tile = (y*8//h)*8+x*8//w
            if tiles.get(tile, 0) == 8:
                decision['rejection'] = 'spatial_selection_limit'; continue
            tiles[tile] = tiles.get(tile, 0)+1; retained.append(candidate)
        pixel_positions = set(); frame_features = []
        for _, pid, index, x, y, decision in retained:
            if (x, y) in pixel_positions:
                decision['rejection'] = 'same_sample_pixel'; continue
            pixel_positions.add((x, y)); descriptions += 1
            require(descriptions <= 8192, 'authoring descriptor budget exceeded')
            frame_features.append(dict(id=index+1, pixel=[x+.5, y+.5], descriptor=descriptor(pixels, w, x, y)))
            bindings.append((pid, iid, index+1)); used.add(pid)
        world_rotation = [[dot(row, column) for column in r] for row in image['rotation']]
        world_translation = [s*a-b for a, b in zip(image['translation'], mv(world_rotation, t))]
        record = dict(reference=iid, recipe_reference=ref, camera_model=cameras[image['camera']], world_to_camera_rotation=world_rotation,
            world_to_camera_translation=world_translation, map_root=map_root, observations=decisions,
            unselected_map_observations=len(image['observations'])-len(decisions), sample_policy='nearest_pixel_center_declared_offset_not_a_new_map_measurement')
        source_records[str(iid)] = record
        if not frame_features:
            rejected.append(iid); continue
        views.append(dict(id=iid, exposure=exposure, pixels=sha(pixels).hex(), image_domain=ref['image_domain_sha256'],
            dimensions=[w, h], mask=sha(mask).hex(), record=hashed(record), features=frame_features))
    require(views and used, 'no usable atlas references; check masks, pose, domain and sampling bounds')
    provenance = dict(schema='fss.atlas-source-manifest/1', recipe_sha256=sha(recipe_data).hex(), recipe=recipe, map_root=map_root,
        references=source_records, empty_references=rejected, unrepresented_landmarks=sorted(set(landmarks)-used),
        descriptor_domain=sha(DOMAIN).hex(), generated_descriptors=descriptions,
        qualification='artifact_consistency_only_not_camera_or_property_accuracy')
    provenance_bytes = canonical(provenance)
    archive = pack_atlas(sha(twin), [landmarks[p] for p in sorted(used)], views, bindings, sha(provenance_bytes))
    return archive, provenance_bytes


def publish(directory, archive, provenance):
    directory = Path(directory)
    directory.mkdir(exist_ok=False)
    def sync_directory():
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    for name, data in [('provenance.json', provenance), ('.atlas.pending', archive)]:
        with (directory / name).open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        require(read(directory / name, 8*MAX_FILE) == data, 'publication readback differs')
    sync_directory()
    os.link(directory / '.atlas.pending', directory / 'atlas.fsatlas')
    sync_directory()
    (directory / '.atlas.pending').unlink()
    sync_directory()
    return dict(status='EXPORTED_NOT_QUALIFIED', atlas_sha256=sha(archive).hex(), provenance_sha256=sha(provenance).hex(), descriptor_domain=sha(DOMAIN).hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        recipe = args.recipe.resolve(); archive, provenance = build(read(recipe, 4*1024*1024), recipe.parent)
        print(json.dumps(publish(args.output_directory, archive, provenance))); return 0
    except (ValueError, OSError, KeyError, TypeError, OverflowError, struct.error, UnicodeError, ImportError, RecursionError):
        print(json.dumps(dict(status='FAILED', reason='atlas source, limits, dependencies, or create-only publication failed; no qualification claimed')), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
