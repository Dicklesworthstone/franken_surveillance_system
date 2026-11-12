#!/usr/bin/env python3
"""Run the scoped trial against a local simulated controller/media peer.

Uses the older laboratory fixture as a protocol oracle and an explicitly
provided synthetic AVC file. No physical camera or real media is contacted.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 4:
        raise SystemExit("expected trial binary, old lab fixture directory, and synthetic AVC file")
    binary, fixture_dir, avc = (str(Path(arg).resolve()) for arg in sys.argv[1:])
    sys.path.insert(0, fixture_dir)
    from media_before_reply_fixture import media_fixture, run_case

    with tempfile.TemporaryDirectory(prefix="fss-scoped-media-") as temporary:
        root = Path(temporary)
        pem, pem_key, cert, key = (root / name for name in ("cert.pem", "key.pem", "cert.der", "key.der"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(pem_key), "-out", str(pem), "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "der", "-out", str(cert)], check=True)
        subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(pem_key), "-outform", "der", "-out", str(key)], check=True)
        os.chmod(key, 0o600)
        run_case(binary, cert, key, root / "capture", media_fixture(avc), True, segments=2)
        clip = root / "capture" / "clip.mp4"
        probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames", "-show_entries", "stream=width,height,nb_read_frames", "-of", "json", str(clip)], capture_output=True, check=True, timeout=20)
        streams = json.loads(probe.stdout)["streams"]
        if len(streams) != 1 or streams[0]["width"] != 2688 or streams[0]["height"] != 1512 or int(streams[0]["nb_read_frames"]) < 6:
            raise ValueError("synthetic high-resolution output did not match")
        subprocess.run(["ffmpeg", "-v", "error", "-xerror", "-i", str(clip), "-map", "0:v:0", "-f", "null", "-"], capture_output=True, check=True, timeout=30)
        print(f"trial_media_fixture media=synthetic width=2688 height=1512 frames={streams[0]['nb_read_frames']} independent_decode=pass")


if __name__ == "__main__":
    main()
