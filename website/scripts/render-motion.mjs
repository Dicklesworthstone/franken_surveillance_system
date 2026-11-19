import { spawn } from "node:child_process";
import { once } from "node:events";
import { pipeline } from "node:stream/promises";
import { readFile, writeFile, rename } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { duration, presets, milestones, fps } from "../lib/motion.js";

export async function encodeFilm(file, rate, frames) {
  const proc = spawn(
    "ffmpeg",
    [
      "-nostdin",
      "-v",
      "error",
      "-y",
      "-f",
      "image2pipe",
      "-framerate",
      String(rate),
      "-vcodec",
      "mjpeg",
      "-i",
      "pipe:0",
      "-an",
      "-threads",
      "2",
      "-c:v",
      "libx264",
      "-crf",
      "19",
      "-pix_fmt",
      "yuv420p",
      "-movflags",
      "+faststart",
      file,
    ],
    { stdio: ["pipe", "ignore", "inherit"] },
  );
  const done = once(proc, "close");
  try {
    const [[code]] = await Promise.all([done, pipeline(frames, proc.stdin)]);
    if (code !== 0) throw Error("Failed to encode " + file);
  } finally {
    if (proc.exitCode === null && proc.signalCode === null) {
      proc.stdin.destroy();
      proc.kill();
      await done;
    }
  }
}

export async function renderMotion(render, stageDir) {
  const index = { parameters: presets[0], seconds: duration, fps, files: {} };
  const paths = [];
  const save = (name) => {
    paths.push(name);
    return join(stageDir, name);
  };
  for (const view of ["studio", "porch", "drive"]) {
    const file = save(view + ".mp4");
    async function* frames() {
      for (let n = 0; n < duration * fps; n++) {
        const jpg = await render("reference", n / fps, view, 768, 432);
        const bytes = Buffer.from(jpg.jpeg, "base64");
        if (n === fps) await writeFile(save(view + ".jpg"), bytes);
        yield bytes;
      }
    }
    await encodeFilm(file, fps, frames());
    console.log(view, duration * fps, "frames");
  }
  const at = milestones(presets[0]);
  for (const [name, id, time, view] of [
    ["pose", "pose", 1.4, "studio"],
    ["release", "reference", at.release, "studio"],
    ["site", "reference", 1.4, "site"],
  ]) {
    const jpg = await render(id, time, view, 1080, 720);
    await writeFile(save(name + ".jpg"), Buffer.from(jpg.jpeg, "base64"));
  }
  for (const file of paths)
    index.files[file] = createHash("sha256")
      .update(await readFile(join(stageDir, file)))
      .digest("hex");
  await writeFile(save("capture.json"), JSON.stringify(index, null, 2) + "\n");
  for (const file of paths)
    await rename(join(stageDir, file), join("public/motion", file));
}
