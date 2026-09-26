"""Real-binary source-gap/assignment-generation/custody contract, not a quality test."""
from pathlib import Path
import sys

from sentinel_detection_cli import document, one, run, sha, snapshot, values

SITE = 'site:package-continuity'
PACKAGE_SHA = 'sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74'


def main():
    file_bin, infer_bin, event_bin, fixture, package, scratch = sys.argv[1:]
    scratch = Path(scratch)
    root = scratch / 'deployment'
    jpeg = Path(fixture).read_bytes()
    # All six images are identical. Junk between complete JPEGs is retained as an omission;
    # it must start a new tracking epoch rather than completing a pre-gap confirmation run.
    footage = jpeg * 3 + b'FSS-SOURCE-GAP-BETWEEN-COMPLETE-FRAMES' + jpeg * 3
    source = scratch / 'gap.mjpeg'
    source.write_bytes(footage)
    imported = run([
        file_bin, 'import', '--root', root, '--site', SITE, '--input', source,
        '--sensor', 'sensor:package-continuity', '--stream', 'stream:package-continuity',
        '--media-format', 'mjpeg', '--receive-time-ns', '10000000000000',
        '--capture-start-ns', '1000000000', '--capture-uncertainty-ns', '1000000',
        '--assumed-fps', '10',
    ])
    import_id = one(imported.stdout, 'import_identity')
    source.unlink()
    base = ['--root', root, '--site', SITE]
    detection = run([
        infer_bin, 'package-detect', *base, '--import-id', import_id,
        '--first-segment', '0', '--frames', '6', '--interpretation', 'ycbcr',
        '--package', package, '--package-digest', PACKAGE_SHA, '--retain', 'yes',
    ])
    report = document(detection.stdout)
    assert len(report['frames']) == 6
    assert report['frames'][3]['capture']['gap_before'] is True
    assert all(len(frame['detections']) == 3 for frame in report['frames'])
    report_id = one(detection.stderr, 'package_detection_retained')
    after_retention = snapshot(root)

    def analyze(hits, path):
        return run([
            event_bin, 'report', *base, '--package-report', report_id, '--label', 'tie',
            '--confirmation-hits', str(hits), '--report-out', path,
        ])

    strict = analyze(4, scratch / 'four-hits.bin')
    assert one(strict.stdout, 'track_count') == '0', 'confirmation crossed missing source footage'
    assert not values(strict.stdout, 'track')
    path = scratch / 'three-hits.bin'
    complete = analyze(3, path)
    assert one(complete.stdout, 'track_count') == '6', 'each three-frame epoch must confirm independently'
    tracks = values(complete.stdout, 'track')
    assert len(set(tracks)) == 6, 'post-gap tracker ids were recycled'
    assert snapshot(root) == after_retention, 'analysis mutated custody'
    encoded = path.read_bytes()
    assert b'FSSPANR2' in encoded and b'fss.package_analysis_report.v2' in encoded
    digest = one(complete.stdout, 'report_digest')
    assert digest == sha(encoded)
    arguments = [*base, '--report', path, '--report-digest', digest, '--track', tracks[0]]
    prepared = run([event_bin, 'prepare', *arguments])
    approval = one(prepared.stdout, 'proposal_digest')
    assert snapshot(root) == after_retention, 'preparation mutated custody'

    # A self-consistently rehashed altered export is not the source-rebuilt analysis.
    changed = bytearray(encoded)
    changed[-1] ^= 1
    altered = scratch / 'altered.bin'
    altered.write_bytes(changed)
    run([event_bin, 'prepare', *base, '--report', altered, '--report-digest', sha(changed),
         '--track', tracks[0]], ok=False)
    # Legacy magic must reach an explicit package-generation refusal, never the luma parser.
    legacy = scratch / 'legacy-magic.bin'
    legacy_bytes = encoded.replace(b'FSSPANR2', b'FSSPANR1', 1)
    legacy.write_bytes(legacy_bytes)
    refusal = run([event_bin, 'prepare', *base, '--report', legacy,
                   '--report-digest', sha(legacy_bytes), '--track', tracks[0]], ok=False)
    assert b'legacy v1 package analysis' in refusal.stderr
    assert snapshot(root) == after_retention

    # Corrupt only test-owned retained source objects after preparation. No original input
    # exists and no model rerun or automatic repair is permitted to hide the missing custody.
    originals = []
    for candidate in root.rglob('*'):
        if not candidate.is_file() or candidate.stat().st_size > len(footage) + 4096:
            continue
        data = candidate.read_bytes()
        offset = data.find(footage)
        if offset >= 0:
            originals.append((candidate, data, offset))
    assert originals, 'retained source object not found; fault was not injected'
    for candidate, data, offset in originals:
        damaged = bytearray(data)
        damaged[offset] ^= 1
        candidate.write_bytes(damaged)
    damaged_state = snapshot(root)
    run([event_bin, 'publish', *arguments, '--proposal-digest', approval], ok=False)
    assert snapshot(root) == damaged_state, 'refused publication repaired or mutated custody'
    # Explicit fixture restoration, not application recovery, returns exactly the old evidence.
    for candidate, data, _ in originals:
        candidate.write_bytes(data)
    published = run([event_bin, 'publish', *arguments, '--proposal-digest', approval])
    assert one(published.stdout, 'operation') == 'published'
    assert one(published.stdout, 'event_kind') == 'unclassified'
    assert one(published.stdout, 'failure_domains') == '1'
    assert one(published.stdout, 'effects_authorized') == 'false'
    after_event = snapshot(root)
    retry = run([event_bin, 'publish', *arguments, '--proposal-digest', approval])
    assert one(retry.stdout, 'operation') == 'already_published'
    assert snapshot(root) == after_event
    print('PASS: source-gap confirmation, v2 report tamper/legacy refusal, custody revalidation and idempotent publication')


if __name__ == '__main__':
    main()
