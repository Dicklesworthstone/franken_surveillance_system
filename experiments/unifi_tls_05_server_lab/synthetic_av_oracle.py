#!/usr/bin/env python3
"""Independent synthetic A/V MP4 decoder check; never contacts a camera."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

stage = "setup"

def run():
    global stage
    if len(sys.argv) != 2:
        raise ValueError("expected Rust test binary")
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="fss-av-oracle-") as folder:
        root = Path(folder)
        stage = "generate_synthetic_audio"
        generated = subprocess.run(
            ["ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i", "anullsrc=r=16000:cl=mono",
             "-frames:a", "1", "-c:a", "aac", "-f", "adts", "pipe:1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
        ).stdout
        if len(generated) < 8 or generated[0] != 0xff or generated[1] & 0xf6 != 0xf0:
            raise ValueError("invalid synthetic ADTS")
        header = 7 if generated[1] & 1 else 9
        length = ((generated[3] & 3) << 11) | (generated[4] << 3) | (generated[5] >> 5)
        if length > len(generated) or length <= header:
            raise ValueError("invalid synthetic AAC length")
        audio = root / "synthetic-aac.bin"
        audio.write_bytes(generated[header:length])
        os.chmod(audio, 0o600)
        movie = root / "synthetic-av.mp4"
        env = dict(os.environ, FSS_SYNTHETIC_AAC_BODY=str(audio), FSS_SYNTHETIC_AV_OUTPUT=str(movie))
        stage = "rust_fixture"
        test = subprocess.run([binary, "--ignored", "--exact", "synthetic_av_for_external_decoder"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60)
        if test.returncode != 0 or not movie.is_file():
            raise ValueError("Rust synthetic A/V fixture failed")
        stage = "probe_streams"
        probe = subprocess.run(["ffprobe", "-v", "error", "-count_frames", "-show_entries",
                                "stream=codec_name,codec_type,sample_rate,channels,nb_read_frames",
                                "-of", "json", str(movie)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=True, timeout=30)
        streams = json.loads(probe.stdout).get("streams", [])
        video = [x for x in streams if x.get("codec_type") == "video"]
        sound = [x for x in streams if x.get("codec_type") == "audio"]
        if (len(video) != 1 or len(sound) != 1 or video[0].get("codec_name") != "h264"
                or sound[0].get("codec_name") != "aac" or sound[0].get("sample_rate") != "16000"
                or sound[0].get("channels") != 1 or video[0].get("nb_read_frames") != "3"
                or sound[0].get("nb_read_frames") != "2"):
            print("synthetic_probe=" + json.dumps(streams))
            raise ValueError("unexpected synthetic streams")
        stage = "decode_streams"
        decoded = subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(movie),
                                  "-map", "0:v:0", "-map", "0:a:0", "-f", "null", "-"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if decoded.returncode or decoded.stderr:
            raise ValueError("independent synthetic decode failed")
        print("synthetic_av=passed video_frames=3 audio_frames=2 sample_rate=16000 channels=1 media=synthetic camera_contact=no")


try:
    run()
except Exception as error:
    print("synthetic_av=failed stage=" + stage + " error_type=" + type(error).__name__)
    raise SystemExit(1)
