// One decoded frame per camera and a model render on the same film clock.
import { spawn } from "node:child_process";
import { once } from "node:events";
import { rename, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { createHash } from "node:crypto";
import {
  cameraAsset,
  cameras,
  cases,
  DURATION,
  recording,
} from "../lib/scenarios.js";

const ffmpeg = (args, input = "ignore") =>
  spawn(
    "ffmpeg",
    ["-nostdin", "-hide_banner", "-loglevel", "error", "-y", ...args],
    { stdio: [input, "inherit", "inherit"] },
  );

export async function renderWall(render, stageDir) {
  const { fps } = recording;
  const width = 512,
    height = 288;
  const labels = [
    "MODEL FLYOVER",
    ...cameras.map((c) => c.label.toUpperCase()),
  ];
  const filters = labels.map(
    (text, i) =>
      `[${i}:v]scale=${width}:${height},setsar=1,drawtext=fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf:text='${text}':fontsize=13:fontcolor=white:box=1:boxcolor=0x102423@0.92:boxborderw=6:x=14:y=14[t${i}]`,
  );
  filters.push(
    "[t0][t1][t2][t3]xstack=inputs=4:layout=0_0|514_0|0_290|514_290:fill=0x102423[out]",
  );
  const manifest = {};
  for (const s of cases) {
    const sources = cameras.map((c) => cameraAsset(s, c.id));
    const film = join(stageDir, s.id + ".mp4"),
      poster = join(stageDir, s.id + ".jpg");
    const proc = ffmpeg(
      [
        "-f",
        "image2pipe",
        "-framerate",
        String(fps),
        "-vcodec",
        "mjpeg",
        "-i",
        "pipe:0",
        ...sources.flatMap((stem) => ["-i", "public/films/" + stem + ".mp4"]),
        "-filter_complex_threads",
        "1",
        "-filter_complex",
        filters.join(";"),
        "-map",
        "[out]",
        "-an",
        "-frames:v",
        String(DURATION * fps),
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-threads",
        "2",
        "-preset",
        "fast",
        "-crf",
        "19",
        "-movflags",
        "+faststart",
        film,
      ],
      "pipe",
    );
    const done = once(proc, "close");
    async function* frames() {
      for (let frame = 0; frame < DURATION * fps; frame++) {
        const view = await render(s.id, frame / fps, "flyover", width, height);
        yield Buffer.from(view.jpeg, "base64");
      }
    }
    try {
      const [[code]] = await Promise.all([
        done,
        pipeline(frames(), proc.stdin),
      ]);
      if (code !== 0) throw Error("FFmpeg failed for " + s.id);
    } finally {
      if (proc.exitCode === null && proc.signalCode === null) {
        proc.stdin.destroy();
        proc.kill();
        await done;
      }
    }
    const [code] = await once(
      ffmpeg(["-ss", "5.5", "-i", film, "-frames:v", "1", "-q:v", "2", poster]),
      "close",
    );
    if (code !== 0) throw Error("Missing poster for " + s.id);
    const digest = async (f) =>
      createHash("sha256")
        .update(await readFile(f))
        .digest("hex");
    manifest[s.id] = {
      fps,
      frames: DURATION * fps,
      film: await digest(film),
      poster: await digest(poster),
      sources: Object.fromEntries(
        await Promise.all(
          sources.map(async (stem) => [
            stem,
            await digest("public/films/" + stem + ".mp4"),
          ]),
        ),
      ),
    };
    console.log(s.id, "wall reel rendered");
  }
  await writeFile(
    join(stageDir, "index.json"),
    JSON.stringify(manifest, null, 2) + "\n",
  );
  for (const name of [
    ...cases.flatMap((s) => [s.id + ".mp4", s.id + ".jpg"]),
    "index.json",
  ])
    await rename(join(stageDir, name), join("public/wall", name));
}
