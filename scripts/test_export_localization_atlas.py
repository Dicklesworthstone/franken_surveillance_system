#!/usr/bin/env python3
"""Execute the actual authoring producer against synthetic files and hostile variants."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import export_localization_atlas as atlas
from test_atlas_archive import inspect


def texture():
    state = 1973; values = []
    for _ in range(96*96):
        state = (state*1664525+1013904223) & 0xffffffff
        values.append(20+((state >> 16) % 180))
    return bytes(values)


def make_twin():
    p = struct.pack
    text = lambda s: p('<H', len(s)) + s
    b = bytes([1])*32+text(b'test/Z-up')+text(b'synthetic')
    b += b'\0'+p('<dddIIII', 0., -1., -1., 1, 1, 4, 2)
    b += text(b'walk')+b'\1'+text(b'ground')+p('<IBB', 0, 1, 1)
    b += b''.join(p('<ddd', *xyz) for xyz in [(0., 0., 0.), (4., 0., 0.), (4., 4., 0.), (0., 4., 0.)])
    b += p('<IIIIIIII', 0, 1, 2, 0, 0, 2, 3, 0)
    b = b'FSSTWIN1'+p('<Q', len(b))+b
    return b+atlas.sha(b)


def fixture(root):
    def put(name, data):
        (root/name).write_bytes(data)
        return dict(path=name, sha256=atlas.sha(data).hex())
    locations = [(25.5, 25.5), (45.5, 26.5), (67.5, 28.5), (28.5, 47.5), (48.5, 48.5), (68.5, 49.5), (24.5, 67.5), (46.5, 69.5), (66.5, 68.5)]
    points, observations, assignments = [], [], {}
    for index, (u, v) in enumerate(locations):
        pid = index*7+3; depth = 3.+index%4
        x, y = (u-48.)*depth/80., (v-48.)*depth/80.
        points.append(f'{pid} {x:.17g} {y:.17g} {depth} 80 90 100 0 1 {index} 2 {index}')
        observations.append(f'{u} {v} {pid}')
        assignments[str(pid)] = dict(feature_id='walk', error=None)
    observations = ' '.join(observations)
    cameras = put('cameras.txt', b'1 PINHOLE 96 96 80 80 48 48\n')
    images = put('images.txt', f'1 1 0 0 0 0 0 0 1 reference.pgm\n{observations}\n2 1 0 0 0 0 0 0 1 second.pgm\n{observations}\n'.encode())
    point_file = put('points3D.txt', ('\n'.join(points)+'\n').encode())
    reference = dict(image_id=1, image_name='reference.pgm', partition='mapping',
        image_domain_kind='undistorted-pinhole-pixel-edge', image_domain_sha256='03'*32,
        image=put('reference.pgm', b'P5\n96 96\n255\n'+texture()),
        allowed_mask=put('allowed.bin', bytes([1])*(96*96)),
        source=dict(sha256='04'*32, stream=0, pts=100, time_base=[1, 30]))
    recipe = dict(schema='fss.colmap-atlas-recipe/1', twin=put('property.fsstwin', make_twin()), source_scene_sha256='01'*32,
        model=dict(cameras=cameras, images=images, points3D=point_file),
        map_to_property=dict(scale=1., rotation=[[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]], translation=[0., 0., 0.]),
        maximum_reference_snap_px=.75, maximum_reprojection_px=3., landmarks=assignments, references=[reference])
    return recipe


class ProducerChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.recipe = fixture(self.root)

    def build(self, recipe=None):
        return atlas.build(atlas.canonical(recipe or self.recipe), self.root)

    def test_real_producer_emits_a_complete_deterministic_archive(self):
        a, sources = self.build(); b, other = self.build()
        self.assertEqual((a, sources), (b, other))
        self.assertEqual(inspect(a), (9, 1, 9))
        self.assertEqual(a[112:144], atlas.sha(sources))
        metadata = json.loads(sources)
        self.assertEqual(metadata['generated_descriptors'], 9)
        self.assertEqual(metadata['unrepresented_landmarks'], [])
        result = atlas.publish(self.root/'out', a, sources)
        self.assertEqual(result['atlas_sha256'], atlas.sha(a).hex())
        self.assertEqual((self.root/'out/atlas.fsatlas').read_bytes(), a)
        self.assertFalse((self.root/'out/.atlas.pending').exists())
        with self.assertRaises(FileExistsError):
            atlas.publish(self.root/'out', a, sources)

    def test_producer_semantic_root_matches_independent_wire_decode(self):
        data, _ = self.build()
        count, refs, links = struct.unpack_from('<III', data, 144)
        offset = 156
        normal = b'fss/localization-atlas/reference/1\0'+data[16:80]+struct.pack('<Q', count)
        for _ in range(count):
            pid, group, feature = struct.unpack_from('<QQI', data, offset)
            size = 77+24*data[offset+76]
            normal += struct.pack('<QQQ', pid, group, feature)+data[offset+20:offset+size]
            offset += size
        normal += struct.pack('<Q', refs)
        for _ in range(refs):
            iid = struct.unpack_from('<Q', data, offset)[0]
            w, h = struct.unpack_from('<II', data, offset+104)
            features = struct.unpack_from('<I', data, offset+176)[0]
            normal += struct.pack('<Q', iid)+data[offset+8:offset+104]+struct.pack('<QQQ', w, h, features)
            offset += 180
            normal += data[offset:offset+56*features]; offset += 56*features
        normal += struct.pack('<Q', links)+data[offset:offset+24*links]
        self.assertEqual(atlas.sha(normal), data[80:112])
        self.assertEqual(offset+24*links, len(data)-32)

    def test_actual_cli_publishes_the_expected_files(self):
        recipe = self.root/'recipe.json'; recipe.write_bytes(atlas.canonical(self.recipe))
        completed = subprocess.run([sys.executable, '-B', str(Path(atlas.__file__).resolve()),
            '--recipe', str(recipe), '--output-directory', str(self.root/'cli')], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result['status'], 'EXPORTED_NOT_QUALIFIED')
        self.assertEqual(result['atlas_sha256'], atlas.sha((self.root/'cli/atlas.fsatlas').read_bytes()).hex())

    def test_descriptor_matches_existing_rust_golden(self):
        self.assertEqual(atlas.descriptor(texture(), 96, 31, 25),
            [7446008588468777431, 4775082772142637252, 7157827042248088871, 8533386832858067528])

    def test_explicit_snap_offsets_are_retained(self):
        data = (self.root/'images.txt').read_text().replace('25.5 25.5', '25.7 25.8')
        (self.root/'images.txt').write_text(data)
        self.recipe['model']['images']['sha256'] = atlas.sha(data.encode()).hex()
        _, sources = self.build()
        record = json.loads(sources)['references']['1']['observations'][0]
        self.assertEqual(record['observed_pixel'], [25.7, 25.8])
        self.assertEqual(record['sampled_pixel'], [25.5, 25.5])
        self.assertAlmostEqual(record['sampling_offset_px'], (.2**2+.3**2)**.5)
        self.recipe['maximum_reference_snap_px'] = 0
        _, sources = self.build()
        self.assertIn(3, json.loads(sources)['unrepresented_landmarks'])

    def test_mask_rejects_the_whole_descriptor_footprint(self):
        mask = bytearray((self.root/'allowed.bin').read_bytes()); mask[25*96+40] = 0
        (self.root/'allowed.bin').write_bytes(mask)
        self.recipe['references'][0]['allowed_mask']['sha256'] = atlas.sha(mask).hex()
        _, sources = self.build()
        record = json.loads(sources)['references']['1']['observations'][0]
        self.assertEqual(record['rejection'], 'masked_footprint')
        self.assertIn(3, json.loads(sources)['unrepresented_landmarks'])

    def test_source_hashes_and_heldout_partitions_fail_closed(self):
        for part in ['image', 'allowed_mask']:
            candidate = copy.deepcopy(self.recipe); candidate['references'][0][part]['sha256'] = '07'*32
            with self.assertRaises(ValueError):
                self.build(candidate)
        for partition in ['final-check', 'held-out']:
            candidate = copy.deepcopy(self.recipe); candidate['references'][0]['partition'] = partition
            with self.assertRaises(ValueError):
                self.build(candidate)

    def test_alias_exposures_do_not_become_independent_views(self):
        second = copy.deepcopy(self.recipe['references'][0]); second.update(image_id=2, image_name='second.pgm')
        second['source']['pts'] = 200; second['source']['time_base'] = [1, 60]; second['source']['note'] = 'does not create another exposure'
        self.recipe['references'].append(second)
        with self.assertRaisesRegex(ValueError, 'reused reference exposure'):
            self.build()

    def test_nonreciprocal_tracks_and_mirrored_frames_fail(self):
        candidate = copy.deepcopy(self.recipe)
        candidate['map_to_property']['rotation'][0][0] = -1
        with self.assertRaises(ValueError):
            self.build(candidate)
        data = (self.root/'points3D.txt').read_text().replace(' 2 0\n', ' 2 1\n')
        (self.root/'points3D.txt').write_text(data); self.recipe['model']['points3D']['sha256'] = atlas.sha(data.encode()).hex()
        with self.assertRaisesRegex(ValueError, 'nonreciprocal'):
            self.build()

    def test_similarity_changes_coordinates_and_camera_once(self):
        candidate = copy.deepcopy(self.recipe)
        candidate['map_to_property'] = dict(scale=2., rotation=[[0., -1., 0.], [1., 0., 0.], [0., 0., 1.]], translation=[5., 6., 7.])
        _, sources = self.build(candidate)
        camera = json.loads(sources)['references']['1']
        r = camera['world_to_camera_rotation']; t = camera['world_to_camera_translation']
        self.assertEqual(r, [[0., 1., 0.], [-1., 0., 0.], [0., 0., 1.]])
        self.assertEqual(t, [-6., 5., -7.])
        self.assertEqual([a+b for a, b in zip(atlas.mv(r, [5., 6., 7.]), t)], [0., 0., 0.])

    def test_empty_point_row_and_filename_spaces_parse(self):
        cameras, images, points = atlas.parse_model('1 PINHOLE 96 96 80 80 48 48\n',
            '1 1 0 0 0 0 0 0 1 a name.pgm\n\n2 1 0 0 0 0 0 0 1 second.pgm\n\n', '')
        self.assertEqual(images[1]['name'], 'a name.pgm')
        self.assertEqual(images[2]['observations'], [])

    def test_pgm_does_not_eat_whitespace_or_hash_in_raster(self):
        for first in [9, 10, 13, 32, 35, 0, 255]:
            self.assertEqual(atlas.gray(b'P5\n# comment\n2 1\n255\n'+bytes([first, 9]))[2], bytes([first, 9]))
        with self.assertRaises(ValueError):
            atlas.gray(b'P5\n2 1\n255\n\0')

    def test_source_paths_cannot_escape(self):
        for path in ['../reference.pgm', '/tmp/reference.pgm', 'https://example.org/image', 'a\\b']:
            candidate = copy.deepcopy(self.recipe); candidate['references'][0]['image']['path'] = path
            with self.assertRaises(ValueError):
                self.build(candidate)
        with tempfile.TemporaryDirectory() as outside:
            p = Path(outside)/'image'; p.write_bytes(b'hello')
            (self.root/'link').symlink_to(p)
            with self.assertRaises(ValueError):
                atlas.member(self.root, 'link')

    def test_failed_publication_never_exposes_partial_root(self):
        data, sources = self.build()
        with patch.object(atlas.os, 'link', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                atlas.publish(self.root/'failed', data, sources)
        self.assertFalse((self.root/'failed/atlas.fsatlas').exists())
        self.assertEqual((self.root/'failed/provenance.json').read_bytes(), sources)
        self.assertEqual((self.root/'failed/.atlas.pending').read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
