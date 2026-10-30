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
    schemas = {
        f'fss.package_zone_report.v{version}': (
            f'package_zone_report.v{version}.json',
            parse_strict_json((repository / f'schemas/package_zone_report.v{version}.json').read_text()),
        )
        for version in (1, 2)
    }

    def checked(output):
        data = document(output.stdout)
        name, schema = schemas[data['schema']]
        validator.validate(schema, data, name)
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

    screened_command = [*command, '--require-health-screening', 'yes']
    head = snapshot(root)
    unknown = checked(run(screened_command))
    assert unknown['schema'] == 'fss.package_zone_report.v2'
    assert unknown['cells'] == preview['cells'] and unknown['frames'] == preview['frames']
    assert unknown['events'] == []
    assert all(f['state'] == 'no_matching_diagnostic' and f['zone_support_allowed'] is False
               for f in unknown['historical_health']['frames'])
    assert unknown['semantics']['source_health_assessed'] is True
    assert unknown['historical_health']['current_camera_health_established'] is False
    assert unknown['historical_health']['native_trace_replayed'] is False
    run([*screened_command, '--retain', approval], ok=False)
    run([*command, '--require-health-screening', 'no'], ok=False)
    run([*read, '--require-health-screening', 'yes'], ok=False)
    assert snapshot(root) == head, 'screening preview or malformed approval changed custody'
    unknown_retained = checked(run([*screened_command, '--retain', unknown['approval_digest']]))
    unknown_read = [event_bin, 'package-zones', 'read', *base,
                    '--report-digest', unknown_retained['report_digest']]
    unknown_cold = checked(run(unknown_read))
    assert unknown_cold['report_digest'] == unknown_retained['report_digest']
    assert unknown_cold['retention_anchor'] == unknown_retained['retention_anchor']
    assert unknown_retained['historical_health']['operation_usage']['retention_indexed_read_attempts'] > 0
    assert unknown_cold['historical_health']['operation_usage']['retention_indexed_read_attempts'] == 0

    def retain_screen(first, count):
        args = [event_bin, 'watch', *base, '--import-id', import_id, '--interpretation', 'ycbcr',
                '--zone', 'image:0,0,32,16', '--first-segment', str(first),
                '--segment-count', str(count), '--stream-watch', '--sensor-health', 'conservative-v1']
        proposal = document(run(args).stdout)['historical_health']
        retained_health = document(run([*args, '--retain-health', proposal['approval_digest']]).stdout)['historical_health']
        assert retained_health['record_digest'] == proposal['record_digest']
        assert retained_health['status'] in ('retained', 'already_retained')
        return retained_health['receipt']

    first_screen = retain_screen(0, 7)
    assert first_screen['status'] == 'no_findings'
    head = snapshot(root)
    run(unknown_read, ok=False)
    partial = checked(run(screened_command))
    assert partial['cells'] == preview['cells']
    exposed = partial['historical_health']['frames']
    assert all(f['zone_support_allowed'] for f in exposed[:7])
    assert all(not f['zone_support_allowed'] for f in exposed[7:])
    usage = partial['historical_health']['operation_usage']
    assert usage['catalog_loads'] == 1 and usage['assessment_work'] == 14
    assert usage['diagnostic_trace_reads'] == 1
    assert any(e['kind'] == 'observation_interrupted' and e['at_frame'] == 7 for e in partial['events'])
    partial_dwells = [e for e in partial['events'] if e['kind'] == 'sampled_dwell']
    assert partial_dwells and all(e['through_frame'] < 7 for e in partial_dwells)
    assert snapshot(root) == head, 'read-only health join mutated custody'

    full_screen = retain_screen(0, 14)
    assert full_screen['status'] == 'suspected_degradation'
    constrained = checked(run(screened_command))
    assert constrained['cells'] == preview['cells'] and constrained['events'] == []
    assert all(f['state'] == 'findings' and not f['zone_support_allowed']
               for f in constrained['historical_health']['frames'])
    assert any(finding['finding'] == 'persistent_bright_field'
               for frame in constrained['historical_health']['frames'] for finding in frame['findings'])
    retained_screened = checked(run([*screened_command, '--retain', constrained['approval_digest']]))
    screened_read = [event_bin, 'package-zones', 'read', *base,
                     '--report-digest', retained_screened['report_digest']]
    head = snapshot(root)
    cold_screened = checked(run(screened_read))
    cold_screened['operation'] = 'retained'
    retained_usage = retained_screened['historical_health'].pop('operation_usage')
    cold_usage = cold_screened['historical_health'].pop('operation_usage')
    assert retained_usage['catalog_loads'] == 3 and cold_usage['catalog_loads'] == 1
    assert retained_usage['retention_indexed_read_bytes_reserved'] > 0
    assert retained_usage['retention_indexed_read_bytes_reserved'] <= retained_usage['retention_indexed_read_byte_limit']
    assert cold_screened == retained_screened, 'v2 cold proof/source/support changed'
    assert checked(run(read))['report_digest'] == retained['report_digest'], 'v1 bytes changed after historical health publication'
    assert snapshot(root) == head
    assert not source.exists() and not package.exists()
    print('PASS: native class-zone v1/v2 custody, unknown/partial/finding health gates, cumulative work, retained cold replay and legacy identity')



if __name__ == '__main__':
    main()
