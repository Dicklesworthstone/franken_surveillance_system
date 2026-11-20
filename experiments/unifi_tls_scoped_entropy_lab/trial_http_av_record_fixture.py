#!/usr/bin/env python3
"""Exercise synthetic A/V; the isolated namespace needs .2 and .3 on loopback."""
from pathlib import Path
import subprocess
import sys

from trial_http_record_fixture import certificate, run


def main():
    if len(sys.argv) != 3:
        raise SystemExit("expected trial binary and private root")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    root = Path(sys.argv[2])
    if not root.is_absolute() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise SystemExit("expected private root")
    cert = certificate(root, "camera")
    avc = Path(__file__).resolve().parent / "tests/support/synthetic_g4_av_gop3.264"
    for mode in ("av_supplied", "av_inband", "av_inband_avc", "av_auto", "av_auto_short", "av_auto_restore", "av_auto_restore_short", "av_auto_restore_drift", "av_changed_avc", "av_bad_readback", "av_short", "av_stale", "av_conflict", "av_name_match", "av_name_opaque", "av_name_mismatch", "av_name_mismatch_drift", "av_auto_name_match", "av_supervised", "av_supervised_rollover", "av_supervised_rollover_exhaust", "av_supervised_no_successor", "av_supervised_denied_successor"):
        run(binary, root, cert, avc, mode)
    for mode in ("av_short", "av_auto_short"):
        run(binary, root, cert, avc, mode, long_tail=True, exhaust_network_after_bootstrap=True)
    run(binary, root, cert, avc, "av_supervised_budget", long_tail=True, exhaust_network_after_bootstrap=True)
    run(binary, root, cert, avc, "av_supervised_framing")
    run(binary, root, cert, avc, "av_bootstrap_framing")
    run(binary, root, cert, avc, "av_supervised_many_tail")
    run(binary, root, cert, avc, "av_short", long_tail=True, exhaust_network_in_bootstrap=True)
    base = [binary, "10.252.15.1:7442", "auto", "auto", str(root / "unused-cert"),
            str(root / "unused-key"), str(root / "unused-effect"), str(root / "unused-archive"),
            "12345678-1234-4abc-9abc-123456789abc", "20"]
    suffix = ["--auto-discovery=24", "--lab-auto-pinned-setup", f"--lab-setup-fence={root / 'unused-fence'}"]
    ending = [f"--lab-http-checkpoint={root / 'unused-checkpoint'}",
              f"--anchored-journal={root / 'unused-keeper'},{root / 'unused-root'}",
              f"--setup-camera=10001,10002,{cert[2]},{root / 'unused-credential'}", "--owner-authorized"]
    cases = (([], "--lab-http-av-record", b"HTTP A/V recording requires an explicit or in-band AAC configuration"),
             (["--lab-aac-config=1408"], "--lab-http-record", b"video-only HTTP recording cannot use an AAC configuration"))
    for audio, mode, expected in cases:
        result = subprocess.run(base + audio + suffix + [mode] + ending, capture_output=True, timeout=15)
        if result.returncode == 0 or expected not in result.stderr:
            raise ValueError("AAC option refusal failed")
    for mode in (("--lab-http-record", "--lab-http-av-auto=1"),):
        result = subprocess.run(base + ["--lab-aac-config=1408"] + suffix + list(mode) + ending, capture_output=True, timeout=15)
        if result.returncode == 0 or b"HTTP A/V automatic generations require A/V recording" not in result.stderr:
            raise ValueError("automatic generation option refusal failed")
    result = subprocess.run(base + ["--lab-aac-config=1408"] + suffix + ["--lab-http-av-record", "--lab-http-av-supervised"] + ending, capture_output=True, timeout=15)
    if result.returncode == 0 or b"HTTP A/V supervision requires automatic A/V recording" not in result.stderr:
        raise ValueError("supervision option refusal failed")
    result = subprocess.run(base + ["--lab-aac-config=1408"] + suffix + ["--lab-http-av-record", "--lab-http-name-probe"] + ending, capture_output=True, timeout=15)
    if result.returncode == 0 or b"HTTP stream-name probe requires recording with restoration" not in result.stderr:
        raise ValueError("A/V name-probe restoration option refusal failed")
    budget_ending = ending[:1] + ["--lab-exhaust-network-after-bootstrap"] + ending[1:]
    result = subprocess.run(base + suffix + ["--lab-http-record"] + budget_ending, capture_output=True, timeout=15)
    if result.returncode == 0 or b"network exhaustion injection requires laboratory HTTP A/V recording" not in result.stderr:
        raise ValueError("network exhaustion option refusal failed")
    conflict_ending = ending[:1] + ["--lab-exhaust-network-in-bootstrap", "--lab-exhaust-network-after-bootstrap"] + ending[1:]
    result = subprocess.run(base + ["--lab-aac-config=1408"] + suffix + ["--lab-http-av-record"] + conflict_ending, capture_output=True, timeout=15)
    if result.returncode == 0 or b"choose one network exhaustion injection stage" not in result.stderr:
        raise ValueError("conflicting network exhaustion options were accepted")
    if any((root / name).exists() for name in ("unused-effect", "unused-archive", "unused-fence", "unused-checkpoint")):
        raise ValueError("AAC option refusal created an effect path")
    print("http_av_argument_refusals passed=7 camera=synthetic")
    print("http_av_record_fixture passed=30 camera=synthetic audio=synthetic")


if __name__ == "__main__":
    main()
