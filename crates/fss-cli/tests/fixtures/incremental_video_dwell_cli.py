"""Real native AVC/HEVC processes and the repository's actual JSON schema validator."""
from pathlib import Path
import shlex
import sys

from sentinel_detection_cli import document, one, run, snapshot


def main():
    file_bin, event_bin, scratch, repository = sys.argv[1:]
    scratch, repository = Path(scratch), Path(repository)
    sys.path.insert(0, str(repository / 'scripts'))
    from json_instance_validate import InstanceValidator, parse_strict_json
    validator = InstanceValidator(repository / 'schemas')
    schema = parse_strict_json((repository / 'schemas/incremental_dwell_progress.v2.json').read_text())

    def checked(output):
        data = document(output.stdout)
        validator.validate(schema, data, 'incremental_dwell_progress.v2.json')
        return data

    def continuation(data, step=None):
        args = shlex.split(data['continuation_command'])
        assert args.pop(0) == 'fss-event'
        if step is not None:
            args[args.index('--dwell-step-frames') + 1] = str(step)
        return [event_bin, *args]

    for label, codec, relative, count, size, screened in [
        ('avc', 'h264', 'long_dwell_h264/square_300.mp4', 300, '48,32', False),
        ('avc-screened', 'h264', 'long_dwell_h264/square_300.mp4', 32, '48,32', True),
        ('hevc', 'h265', 'hevc_ingest/watch_96x48_moving.mp4', 14, '96,48', False),
        ('hevc-screened', 'h265', 'hevc_ingest/watch_96x48_moving.mp4', 14, '96,48', True),
    ]:
        root = scratch / label / 'deployment with spaces'
        root.parent.mkdir()
        source = scratch / (label + '.mp4')
        source.write_bytes((repository / 'crates/fss-reference/tests/fixtures' / relative).read_bytes())
        base = ['--root', root, '--site', 'site:incremental-video-cli']
        imported = run([file_bin, 'import', *base, '--input', source,
                        '--sensor', 'sensor:video', '--stream', 'stream:video',
                        '--receive-time-ns', '1000000000000', '--capture-start-ns', '0',
                        '--capture-uncertainty-ns', '0', '--assumed-fps', '10'])
        identity = one(imported.stdout, 'import_identity')
        source.unlink()
        watch = [event_bin, 'watch', *base, '--import-id', identity, '--interpretation', 'ycbcr',
                 '--zone', 'porch:0,0,' + size, '--stream-dwell', '--segment-count', str(count),
                 '--dwell-for-ns', '20000000000' if count == 300 else '1',
                 '--dwell-max-gap-ns', '1000000000']
        if screened:
            watch += ['--sensor-health', 'conservative-v1']
        if label == 'avc-screened':
            # B-frame display order fragments finding runs in original coding coordinates.
            # The existing 128-run diagnostic ceiling must refuse the full 300-frame scan;
            # a 32-input prefix fits even if every one of the four kinds starts a fresh run.
            oversized = list(watch)
            oversized[oversized.index('--segment-count') + 1] = '300'
            oversized[oversized.index('--dwell-for-ns') + 1] = '20000000000'
            before = snapshot(root)
            for extra in ([], ['--dwell-step-frames', '300']):
                denied = run([*oversized, *extra], ok=False)
                assert b'ERR-WATCH-LIMIT-001' in denied.stderr, denied.stderr
                assert snapshot(root) == before, 'health-bound refusal mutated custody or retained a checkpoint'
            print(label, '300-frame native and incremental diagnostic-bound refusals verified')
        whole = document(run(watch).stdout)
        step = 299 if count == 300 else 5
        first = checked(run([*watch, '--dwell-step-frames', str(step)]))
        assert first['schema'] == 'fss.incremental_dwell_progress.v2'
        assert first['status'] == 'checkpointed' and first['analysis_complete'] is False
        assert first['inter_coded_progress']['codec'] == codec
        assert first['inter_coded_progress']['display_frames_processed'] == step
        assert first['inter_coded_progress']['decoder_drained'] is False
        assert first['new_display_frames'] == step
        assert first['cold_inter_coded_restoration'] is None
        if count == 300:
            assert first['next_segment'] == count and first['remaining_segments'] == 0
            assert first['logical_scan_work']['frames_decoded'] == count - 1
        if screened:
            before = snapshot(root)
            denied = run([*continuation(first), '--retain-health', first['checkpoint_digest']], ok=False)
            assert b'requires an already complete checkpoint' in denied.stderr
            assert snapshot(root) == before, 'incomplete health retention mutated custody'
        current = first
        while not current['analysis_complete']:
            previous = current
            current = checked(run(continuation(previous, 1 if count == 300 else 5)))
            assert current['cold_inter_coded_restoration'] == previous['inter_coded_progress']
            assert current['cold_restoration_work'] == previous['logical_scan_work']
            prior_frames = previous['inter_coded_progress']['display_frames_processed']
            frames = current['inter_coded_progress']['display_frames_processed']
            assert prior_frames <= frames <= count
            assert current['new_display_frames'] == frames - prior_frames
            assert current['analysis_complete'] or frames > prior_frames, 'nonterminal continuation made no display progress'
        assert current['inter_coded_progress']['decoder_drained'] is True
        assert current['logical_scan_work']['frames_decoded'] == count
        if count == 300:
            assert current['new_source_positions'] == 0 and current['new_display_frames'] == 1
        native = current['event_report']
        assert native['analysis_digest'] == whole['analysis_digest']
        assert native['analysis_root'] == whole['analysis_root']
        assert native['candidate_count'] == whole['candidate_count']
        assert [c['proposal_digest'] for c in native['candidates']] == [c['proposal_digest'] for c in whole['candidates']]
        if not screened and native['candidates']:
            command = shlex.split(native['candidates'][0]['publish_command'])
            assert command.pop(0) == 'fss-event'
            published = checked(run([event_bin, *command]))
            assert published['new_source_positions'] == published['new_display_frames'] == 0
            assert published['event_report']['candidates'][0]['status'] == 'published'
            retry = checked(run([event_bin, *command]))
            assert retry['event_report']['candidates'][0]['status'] == 'already_published'
        print(label, 'native cold continuation and schema verified')


if __name__ == '__main__':
    main()
