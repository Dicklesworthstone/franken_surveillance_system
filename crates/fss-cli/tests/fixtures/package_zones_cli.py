"""Native numeric FMPK fixture; Python checks actual JSON/custody, not detector quality."""
from pathlib import Path
import sys

from sentinel_detection_cli import document, one, run, snapshot


def main():
    file_bin, infer_bin, event_bin, source, package, package_digest, scratch, repository = sys.argv[1:]
    source, package, scratch, repository = map(Path, (source, package, scratch, repository))
    sys.path.insert(0, str(repository / 'scripts'))
    from json_instance_validate import InstanceValidator, parse_strict_json
    validator = InstanceValidator(repository / 'schemas')
    schema = parse_strict_json((repository / 'schemas/package_zone_report.v1.json').read_text())

    def checked(output):
        data = document(output.stdout)
        validator.validate(schema, data, 'package_zone_report.v1.json')
        return data

    root = scratch / 'deployment'
    base = ['--root', root, '--site', 'site:package-zones-cli']
    imported = run([file_bin, 'import', *base, '--input', source, '--sensor', 'sensor:package-zones-cli',
                    '--stream', 'stream:package-zones-cli', '--media-format', 'mjpeg',
                    '--receive-time-ns', '10000000000', '--capture-start-ns', '1000000000',
                    '--capture-uncertainty-ns', '1000000', '--assumed-fps', '10'])
    import_id = one(imported.stdout, 'import_identity')
    source.unlink()
    detected = run([infer_bin, 'package-detect', *base, '--import-id', import_id,
                    '--first-segment', '0', '--frames', '14', '--interpretation', 'ycbcr',
                    '--package', package, '--package-digest', package_digest, '--retain', 'yes'])
    native = document(detected.stdout)
    report_id = one(detected.stderr, 'package_detection_retained')
    package.unlink()
    command = [event_bin, 'package-zones', 'analyze', *base, '--package-report', report_id,
               '--label', 'numeric-a', '--zone', 'yard:14:0:14:16', '--maximum-sample-gap-ns', '110000000',
               '--dwell-ns', '180000000', '--minimum-observations', '3', '--confirmation-hits', '2',
               '--maximum-missed-frames', '1', '--minimum-iou-ppm', '0']
    before = snapshot(root)
    preview = checked(run(command))
    assert snapshot(root) == before, 'analysis changed custody'
    assert preview['operation'] == 'analyzed' and preview['retained'] is False
    assert preview['source']['label'] == 'numeric-a' and preview['source']['class_index'] == 0
    assert preview['source']['package_digest'] == package_digest
    assert preview['source']['capture_time_label'] == 'operator_assumption'
    assert preview['source']['clock_basis'] == 'estimated'
    assert len(preview['tracks']) == 1 and len(preview['frames']) == len(preview['cells']) == 14
    assert preview['cells'][0]['sample_confirmed'] is False
    assert preview['cells'][1]['sample_confirmed'] is True
    assert preview['cells'][10]['relation'] == 'unobserved' and preview['cells'][10]['detection_row'] is None
    assert any(d['class_index'] == 1 for d in native['frames'][10]['detections']), 'other class fixture absent'
    for cell in preview['cells']:
        frame = native['frames'][cell['frame']]
        assert preview['frames'][cell['frame']]['capsule_digest'] == frame['capsule_digest']
        if cell['detection_row'] is not None:
            assigned = [d for d in frame['detections'] if d['class_index'] == 0 and d['row'] == cell['detection_row']]
            assert len(assigned) == 1, assigned
            assert cell['bounds'] == assigned[0]['bounds_subpixel'], (cell, assigned)
    entries = [e for e in preview['events'] if e['kind'] == 'entered_between_observations']
    dwells = [e for e in preview['events'] if e['kind'] == 'sampled_dwell']
    assert len(entries) == 1 and entries[0]['from_frame'] == 1, entries
    assert len(dwells) == 2, dwells
    assert dwells[0]['through_frame'] < 10 < dwells[1]['from_frame']
    assert all(int(d['minimum_duration_ns']) >= 180000000 for d in dwells)
    assert not any(e['kind'] == 'left_between_observations' for e in preview['events'])
    assert all(value is False for value in preview['semantics'].values())
    approval = preview['approval_digest']
    run([*command, '--retain', 'sha256:' + 'ab' * 32], ok=False)
    run([*command, '--principal', 'principal:other', '--retain', approval], ok=False)
    changed = list(command)
    changed[changed.index('yard:14:0:14:16')] = 'yard:14:0:14:16:1'
    run([*changed, '--retain', approval], ok=False)
    assert snapshot(root) == before, 'refused approval changed custody'

    retained = checked(run([*command, '--retain', approval]))
    assert retained['operation'] == 'retained' and retained['retained'] is True
    assert retained['report_digest'] == preview['report_digest']
    head = snapshot(root)
    retry = checked(run([*command, '--retain', approval]))
    assert retry['operation'] == 'already_retained'
    assert retry['retention_anchor'] == retained['retention_anchor']
    assert snapshot(root) == head, 'exact retry mutated custody'
    read = [event_bin, 'package-zones', 'read', *base, '--report-digest', retained['report_digest']]
    cold = checked(run(read))
    assert cold['operation'] == 'read_verified'
    cold['operation'] = 'retained'
    assert cold == retained, 'cold native derivation or source/approval/proof bindings changed'
    assert snapshot(root) == head
    run([*read, '--label', 'numeric-b'], ok=False)
    assert snapshot(root) == head

    matches = []
    for path in root.rglob('*'):
        if path.is_file() and path.stat().st_size <= 8 * 1024 * 1024:
            data = path.read_bytes()
            if b'FSSPZNR1' in data:
                matches.append((path, data))
    assert len(matches) == 1, [str(path) for path, _ in matches]
    path, data = matches[0]
    corrupted = bytearray(data)
    corrupted[-1] ^= 1
    path.write_bytes(corrupted)
    damaged = snapshot(root)
    run(read, ok=False)
    run([*command, '--retain', approval], ok=False)
    assert snapshot(root) == damaged, 'refused cold read or retry repaired damaged proof'
    path.write_bytes(data)
    assert checked(run(read))['report_digest'] == retained['report_digest']
    assert not source.exists() and not package.exists()
    print('PASS: native package class/assignment/confirmation/entry/dwell, approved retention, cold exact read and proof refusal')


if __name__ == '__main__':
    main()
