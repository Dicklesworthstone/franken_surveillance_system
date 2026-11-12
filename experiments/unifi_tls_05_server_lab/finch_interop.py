#!/usr/bin/env python3
"""Run one disposable, loopback-only Finch/Rust trial interoperability case."""
import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

FINCH_REV = "97c338adda3d6f9cfa35703c464826c37c12d63d"
WIRE_REV = "ab424de6426826a9fba4cab7b5e20684355fea66"


def check_checkout(path, revision):
    actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(path), "status", "--porcelain"], text=True)
    if actual != revision or dirty:
        raise ValueError(f"oracle checkout must be clean and at {revision}: {path}")


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def verify_cadence(clip, selector, step_ms, expected_frames):
    probe = subprocess.check_output(
        ["ffprobe", "-v", "error", "-select_streams", selector, "-show_entries", "packet=pts_time",
         "-of", "json", str(clip)], text=True, timeout=30)
    packets = json.loads(probe)["packets"]
    if len(packets) != expected_frames or not packets or len(packets) > 1000:
        raise RuntimeError(f"unexpected packet count for {selector}: {len(packets)}")
    times = [Decimal(packet["pts_time"]) for packet in packets]
    expected_step = Decimal(step_ms) / 1000
    if times[0] != 0 or any(not time.is_finite() for time in times):
        raise RuntimeError(f"invalid initial packet timestamp for {selector}")
    if any(right - left != expected_step for left, right in zip(times, times[1:])):
        raise RuntimeError(f"noncontiguous packet timestamps for {selector}")
    return len(times)


def verify_video_content(source, clip, expected_frames):
    if not 1 <= expected_frames <= 1000:
        raise RuntimeError("video content comparison is limited to 1000 output frames")
    def hashes(path, limit):
        output = subprocess.check_output(
            ["ffmpeg", "-v", "error", "-xerror", "-threads", "1", "-i", str(path),
             "-map", "0:v:0", "-frames:v", str(limit), "-fps_mode", "passthrough",
             "-f", "framemd5", "-"], text=True, timeout=120)
        rows = [line.rsplit(",", 1)[-1].strip() for line in output.splitlines()
                if line and not line.startswith("#")]
        if any(len(row) != 32 or any(ch not in "0123456789abcdef" for ch in row) for row in rows):
            raise RuntimeError("invalid FFmpeg frame digest")
        return rows

    source_frames = hashes(source, 1001)
    actual = hashes(clip, expected_frames)
    if not 1 <= len(source_frames) <= 1000 or len(actual) != expected_frames:
        raise RuntimeError("unexpected frame count in content comparison")
    if any(digest != source_frames[index % len(source_frames)] for index, digest in enumerate(actual)):
        raise RuntimeError("decoded video differs from the looping synthetic source")
    return len(actual)


def verify_audio_content(source, clip, expected_frames):
    if not 1 <= expected_frames <= 1000:
        raise RuntimeError("audio content comparison is limited to 1000 output frames")

    def frames(data):
        if not data or len(data) > 32 * 1024 * 1024:
            raise RuntimeError("invalid synthetic ADTS byte count")
        result = []
        offset = 0
        while offset < len(data):
            header = data[offset:offset + 7]
            if (len(header) != 7 or header[:2] != b"\xff\xf1" or
                    (header[2] >> 6) + 1 != 2 or (header[2] >> 2) & 15 != 8 or
                    ((header[2] & 1) << 2 | header[3] >> 6) != 1 or header[6] & 3):
                raise RuntimeError("expected 16 kHz mono AAC-LC ADTS")
            size = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5)
            if size <= 7 or offset + size > len(data):
                raise RuntimeError("invalid ADTS frame length")
            result.append(data[offset + 7:offset + size])
            if len(result) > 1000:
                raise RuntimeError("too many ADTS frames")
            offset += size
        return result

    source_frames = frames(source.read_bytes())
    output = subprocess.check_output(
        ["ffmpeg", "-v", "error", "-xerror", "-i", str(clip), "-map", "0:a:0",
         "-c:a", "copy", "-f", "adts", "-"], timeout=30)
    actual = frames(output)
    if len(actual) != expected_frames:
        raise RuntimeError("unexpected audio packet count in content comparison")
    if any(frame != source_frames[index % len(source_frames)] for index, frame in enumerate(actual)):
        raise RuntimeError("AAC packets differ from the looping synthetic source")
    return len(actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finch", type=Path, required=True, help="clean pinned Finch checkout")
    parser.add_argument("--wire", type=Path, required=True, help="clean pinned pyunifiwire checkout")
    parser.add_argument("--trial", type=Path, required=True, help="Linux experimental Rust trial binary")
    parser.add_argument("--source", type=Path, required=True, help="synthetic Annex B source")
    parser.add_argument("--audio-source", type=Path, help="synthetic 16 kHz mono AAC-LC ADTS")
    parser.add_argument("--codec", choices=("avc", "hevc"), required=True)
    parser.add_argument("--channel", choices=(1, 2, 3), type=int,
                        help="request and verify a specific video channel; needs a compatible trial")
    parser.add_argument("--framing", choices=("conservative", "zero-stream-id"), default="conservative",
                        help="explicit laboratory framing assumption")
    parser.add_argument("--fps", type=int, default=15, help="synthetic source cadence, 1 through 60")
    parser.add_argument("--segments", type=int, default=1, help="bounded segment count, 1 through 8")
    parser.add_argument("--min-video-frames", type=int, default=3,
                        help="minimum independently decoded video frames, 1 through 1000")
    parser.add_argument("--min-audio-frames", type=int, default=3,
                        help="minimum independently decoded audio frames, 1 through 1000")
    parser.add_argument("--check-cadence", action="store_true",
                        help="require synthetic zero-based constant video and audio packet steps")
    parser.add_argument("--compare-video-source", action="store_true",
                        help="compare decoded output frames with the looping synthetic input")
    parser.add_argument("--compare-audio-source", action="store_true",
                        help="compare AAC packet bodies with the looping synthetic input")
    parser.add_argument("--width", type=int, default=0, help="expected AVC width")
    parser.add_argument("--height", type=int, default=0, help="expected AVC height")
    args = parser.parse_args()
    if not 1 <= args.fps <= 60:
        parser.error("--fps must be between 1 and 60")
    if not 1 <= args.segments <= 8:
        parser.error("--segments must be between 1 and 8")
    if not 1 <= args.min_video_frames <= 1000:
        parser.error("--min-video-frames must be between 1 and 1000")
    if not 1 <= args.min_audio_frames <= 1000:
        parser.error("--min-audio-frames must be between 1 and 1000")
    if (args.check_cadence or args.compare_video_source or args.compare_audio_source) and args.codec != "avc":
        parser.error("cadence and content checking require synthetic AVC")
    if args.compare_audio_source and args.audio_source is None:
        parser.error("--compare-audio-source requires --audio-source")
    for name in ("finch", "wire", "trial", "source"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    if args.audio_source is not None:
        if args.codec != "avc":
            parser.error("synthetic audio requires the AVC adapter")
        args.audio_source = args.audio_source.resolve(strict=True)
    if args.codec == "avc" and (args.width <= 0 or args.height <= 0):
        parser.error("AVC requires positive --width and --height")
    check_checkout(args.finch, FINCH_REV)
    check_checkout(args.wire, WIRE_REV)

    run = Path(tempfile.mkdtemp(prefix="fss-finch-interop-"))
    os.chmod(run, 0o700)
    env = os.environ.copy()
    env.pop("FSS_SYNTHETIC_AAC", None)
    env.update(FSS_FINCH_DIR=str(args.finch), FSS_WIRE_DIR=str(args.wire),
               PYTHONPATH=str(args.wire / "src"))
    if args.audio_source is not None:
        env["FSS_SYNTHETIC_AAC"] = str(args.audio_source)
    key, cert = run / "key.pem", run / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-subj", "/CN=localhost", "-days", "1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key, 0o600)
    subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER", "-out", str(run / "cert.der")], check=True)
    subprocess.run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-outform", "DER", "-out", str(run / "key.der")], check=True)
    os.chmod(run / "key.der", 0o600)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    trial = [str(args.trial), f"127.0.0.1:{port}", "127.0.0.1", "28704ef17c40",
             str(run / "cert.der"), str(run / "key.der"), str(run / "journal"),
             str(run / "clip.mp4"), "12345678-1234-4abc-9abc-123456789abc", "20"]
    if args.channel is not None:
        trial.append(f"--video-channel={args.channel}")
    trial.extend(["--media-before-reply", "--reply-events", "--reply-startup-requests"])
    if args.audio_source is not None:
        trial.append("--lab-aac-source")
    if args.framing == "zero-stream-id":
        trial.append("--lab-zero-stream-id")
    if args.segments != 1:
        trial.append(f"--lab-segments={args.segments}")
    trial.append("--owner-authorized")
    camera_script = Path(__file__).with_name("finch_avc_shim.py") if args.codec == "avc" else args.finch / "main.py"
    camera = [sys.executable, str(camera_script), "--host", "127.0.0.1", "--port", str(port),
              "--token", "synthetic-token", "--cert", str(run / "finch.pem"),
              "--source", str(args.source), "--fps", str(args.fps), "--once", "--verbose"]
    controller_proc = camera_proc = None
    try:
        with (run / "trial.log").open("wb") as controller_log, (run / "finch.log").open("wb") as camera_log:
            controller_proc = subprocess.Popen(trial, cwd=run, stdout=controller_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while b"controller_listener_ready" not in (run / "trial.log").read_bytes():
                if controller_proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("trial listener did not become ready")
                time.sleep(0.05)
            camera_proc = subprocess.Popen(camera, cwd=run, env=env, stdout=camera_log, stderr=subprocess.STDOUT)
            controller_proc.wait(timeout=35)
            camera_proc.wait(timeout=8)
    finally:
        stop(camera_proc)
        stop(controller_proc)
        print(f"retained_case={run}", flush=True)

    log = (run / "trial.log").read_text()
    camera_log = (run / "finch.log").read_text()
    clip = run / "clip.mp4"
    sha256 = hashlib.sha256(args.trial.read_bytes()).hexdigest()
    if args.channel is not None and (f"trial_video_channel=Video{args.channel}" not in log or
                                     f"armed video{args.channel} ->" not in camera_log):
        raise RuntimeError("the requested channel was not observed at both ends")
    if args.codec == "hevc":
        if controller_proc.returncode == 0 or clip.exists() or "UnsupportedVideo" not in log:
            raise RuntimeError("HEVC was not explicitly refused as expected")
        print(f"result=expected_hevc_refusal trial_sha256={sha256}")
        return
    if controller_proc.returncode != 0 or camera_proc.returncode != 0 or not clip.is_file():
        raise RuntimeError("AVC case did not produce a completed clip")
    if "trial_complete" not in log or "effects=reconciliation_required" not in log:
        raise RuntimeError("trial did not report completion with reconciliation qualification")
    if f"trial_stage=segment_assembled count={args.segments}" not in log:
        raise RuntimeError("trial did not report the requested segment count")
    probe = subprocess.check_output(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames",
                                     "-show_entries", "stream=codec_name,width,height,nb_read_frames",
                                     "-of", "json", str(clip)], text=True)
    stream = json.loads(probe)["streams"][0]
    if (stream["codec_name"] != "h264" or stream["width"] != args.width or
            stream["height"] != args.height or int(stream["nb_read_frames"]) < args.min_video_frames):
        raise RuntimeError(f"unexpected independently probed stream: {stream}")
    audio = None
    if args.audio_source is not None:
        audio_probe = subprocess.check_output(["ffprobe", "-v", "error", "-select_streams", "a:0", "-count_frames",
                                               "-show_entries", "stream=codec_name,sample_rate,channels,nb_read_frames",
                                               "-of", "json", str(clip)], text=True)
        audio = json.loads(audio_probe)["streams"][0]
        if (audio["codec_name"] != "aac" or audio["sample_rate"] != "16000" or
                audio["channels"] != 1 or int(audio["nb_read_frames"]) < args.min_audio_frames):
            raise RuntimeError(f"unexpected independently probed audio: {audio}")
    cadence = None
    if args.check_cadence:
        cadence = {"video_packets": verify_cadence(clip, "v:0", round(1000 / args.fps),
                                                   int(stream["nb_read_frames"]))}
        if audio is not None:
            cadence["audio_packets"] = verify_cadence(clip, "a:0", 64, int(audio["nb_read_frames"]))
    decode = ["ffmpeg", "-v", "error", "-xerror", "-threads", "1", "-i", str(clip), "-map", "0:v:0"]
    if audio is not None:
        decode.extend(["-map", "0:a:0"])
    decode.extend(["-f", "null", "-"])
    subprocess.run(decode, check=True, stdout=subprocess.DEVNULL, timeout=30)
    content_frames = None
    if args.compare_video_source:
        content_frames = verify_video_content(args.source, clip, int(stream["nb_read_frames"]))
    content_audio_packets = None
    if args.compare_audio_source:
        content_audio_packets = verify_audio_content(args.audio_source, clip, int(audio["nb_read_frames"]))
    print(f"result=synthetic_avc_clip trial_sha256={sha256} channel={args.channel or 'trial_default'} framing={args.framing} requested_fps={args.fps} segments={args.segments} stream={json.dumps(stream, sort_keys=True)} audio={json.dumps(audio, sort_keys=True)} cadence={json.dumps(cadence, sort_keys=True)} content_frames={content_frames} content_audio_packets={content_audio_packets}")


if __name__ == "__main__":
    main()
