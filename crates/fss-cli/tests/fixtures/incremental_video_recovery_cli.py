"""Actual native import/watch processes recovering from retained AVC/HEVC damage.

Python only constructs deterministic corrupt fixture bytes, parses complete JSON,
and observes process/filesystem results. Production decoding and checkpoint replay
run through the genuine FSS binaries, including after the loose source is removed.
"""

from pathlib import Path
import re
import shlex
import sys

from sentinel_detection_cli import document, one, run, snapshot


def damaged_avc(original):
    starts = list(re.finditer(rb"\x00\x00\x00?\x01", original))
    payload = starts[6].end()
    following = starts[7].start()
    assert payload + 20 < following
    return original[:payload + 20] + original[following:] + original


def damaged_hevc(original):
    last = original.rfind(b"\x00\x00\x01")
    assert last > 0
    return original[:last + (len(original) - last) // 2] + original


def main():
    file_bin, event_bin, scratch, repository = sys.argv[1:]
    scratch, repository = Path(scratch), Path(repository)
    sys.path.insert(0, str(repository / "scripts"))
    from json_instance_validate import InstanceValidator, parse_strict_json
    validator = InstanceValidator(repository / "schemas")
    name = "incremental_dwell_progress.v3.json"
    schema = parse_strict_json((repository / "schemas" / name).read_text())

    def checked(output):
        result = document(output.stdout)
        validator.validate(schema, result, name)
        assert result["schema"] == "fss.incremental_dwell_progress.v3"
        assert result["checkpoint_is_event"] is False
        assert result["absence_certifiable"] is False
        assert result["alert_authorized"] is False
        assert result["inter_coded_progress"]["step_unit"] == "continuation_items"
        return result

    def continuation(result):
        command = shlex.split(result["continuation_command"])
        assert command.pop(0) == "fss-event"
        assert "--tolerate-decode-refusals" in command
        return [event_bin, *command]

    cases = [
        ("avc", "annexb", "h264", "fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264",
         damaged_avc, 24, 3, 11),
        ("hevc", "hevc", "h265", "fss-codec-h265/tests/fixtures/decode/i_qcif_cra.h265",
         damaged_hevc, 6, 2, 2),
    ]
    for label, media_format, codec, fixture, damage, count, refused_first, refused_last in cases:
        directory = scratch / label
        directory.mkdir()
        root = directory / "deployment with spaces"
        source = directory / ("damaged." + codec)
        source.write_bytes(damage((repository / "crates" / fixture).read_bytes()))
        base = ["--root", root, "--site", "site:incremental-recovery-cli"]
        imported = run([
            file_bin, "import", *base, "--input", source, "--media-format", media_format,
            "--sensor", "sensor:recovery", "--stream", "stream:recovery",
            "--receive-time-ns", "1000000000000", "--capture-start-ns", "0",
            "--capture-uncertainty-ns", "0", "--assumed-fps", "10",
        ])
        identity = one(imported.stdout, "import_identity")
        source.unlink()
        watch = [
            event_bin, "watch", *base, "--import-id", identity,
            "--interpretation", "ycbcr", "--zone", "whole:0,0,176,144",
            "--stream-dwell", "--segment-count", str(count),
            "--dwell-for-ns", "1", "--dwell-max-gap-ns", "1000000000",
            "--max-dimension", "256", "--max-pixels", "65536",
        ]
        before = snapshot(root)
        for extra in ([], ["--dwell-step-frames", str(count)]):
            denied = run([*watch, *extra], ok=False)
            assert b"ERR-" in denied.stderr
            assert snapshot(root) == before, "strict refusal retained partial work"
        tolerant = [*watch, "--tolerate-decode-refusals"]
        whole = document(run(tolerant).stdout)
        assert snapshot(root) == before
        assert [(r["first_segment"], r["last_segment"]) for r in whole["decode_refusals"]] == [
            (refused_first, refused_last)
        ]
        first_command = [*tolerant, "--dwell-step-frames", "1"]
        current = checked(run(first_command))
        after_first = snapshot(root)
        retry = checked(run(first_command))
        assert retry["checkpoint_digest"] == current["checkpoint_digest"]
        assert retry["checkpoint_root"] == current["checkpoint_root"]
        assert snapshot(root) == after_first, "exact retry appended another checkpoint"

        altered = [arg for arg in continuation(current) if arg != "--tolerate-decode-refusals"]
        run(altered, ok=False)
        assert snapshot(root) == after_first, "mode substitution changed retained custody"
        denied = continuation(current)
        admission = denied.index("--dwell-restore-max-frames") + 1
        denied[admission] = str(current["logical_scan_work"]["source_positions"] - 1)
        run(denied, ok=False)
        assert snapshot(root) == after_first, "insufficient replay admission changed custody"

        saw_gap_only_step = False
        for _ in range(2 * count + 2):
            if current["analysis_complete"]:
                break
            previous = current
            current = checked(run(continuation(previous)))
            assert current["cold_inter_coded_restoration"] == previous["inter_coded_progress"]
            assert current["cold_restoration_work"] == previous["logical_scan_work"]
            progress = current["inter_coded_progress"]
            prior = previous["inter_coded_progress"]
            recovery, old_recovery = progress["recovery"], prior["recovery"]
            assert progress["codec"] == codec
            assert current["new_display_frames"] == (
                progress["display_frames_processed"] - prior["display_frames_processed"]
            )
            items = recovery["continuation_items_processed"]
            prior_items = old_recovery["continuation_items_processed"]
            assert prior_items <= items <= prior_items + 1
            assert current["analysis_complete"] or items > prior_items
            if recovery["discontinuities"] > old_recovery["discontinuities"]:
                assert current["new_display_frames"] == 0
                saw_gap_only_step = True
            assert recovery["decode_encoded_bytes"] >= old_recovery["decode_encoded_bytes"]
            assert recovery["decode_coded_luma_capacity"] >= old_recovery["decode_coded_luma_capacity"]
        assert current["analysis_complete"], "finite recording did not finish"
        assert saw_gap_only_step, "no checkpoint retained the explicit discontinuity boundary"
        progress = current["inter_coded_progress"]
        recovery = progress["recovery"]
        assert progress["decoder_drained"] is True
        assert progress["source_segments_consumed"] == count
        assert recovery["refused_segments"] == refused_last - refused_first + 1
        assert recovery["decode_refusals"] == whole["decode_refusals"]
        assert progress["display_frames_processed"] + recovery["refused_segments"] + len(
            progress["skipped_rasl_segments"]
        ) == count
        native = current["event_report"]
        for key in ("analysis_digest", "analysis_root", "candidate_count", "decode_refusals"):
            assert native[key] == whole[key], (label, key)
        assert [c["proposal_digest"] for c in native["candidates"]] == [
            c["proposal_digest"] for c in whole["candidates"]
        ]
        terminal = snapshot(root)
        repeated = checked(run(continuation(current)))
        assert repeated["checkpoint_digest"] == current["checkpoint_digest"]
        assert repeated["checkpoint_root"] == current["checkpoint_root"]
        assert repeated["new_display_frames"] == repeated["new_source_positions"] == 0
        assert snapshot(root) == terminal, "completed cold retry changed custody"
        print(label, "damaged-source native recovery, cold checkpoints and v3 schema verified")


if __name__ == "__main__":
    main()
