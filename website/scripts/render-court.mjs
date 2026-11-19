import { createHash } from "node:crypto";
import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { encodeFilm } from "./render-motion.mjs";
import { conditions, clipSeconds, frameRate, passAt } from "../lib/pass.js";

export async function renderCourt(render, dir) {
  const p = conditions[0],
    q = passAt(p, 0);
  const capture = {
    parameters: p,
    seconds: clipSeconds,
    fps: frameRate,
    assets: {},
    files: {},
  };
  for (const name of [
    "passer.glb",
    "receiver.glb",
    "garden.hdr",
    "garden.webp",
  ])
    capture.assets[name] = createHash("sha256")
      .update(await readFile(join("public/court", name)))
      .digest("hex");
  const save = async (name, jpg) =>
    writeFile(join(dir, name), Buffer.from(jpg.jpeg, "base64"));
  const names = [];
  for (const view of ["wide", "garden", "patio"]) {
    async function* frames() {
      for (let i = 0; i < clipSeconds * frameRate; i++) {
        const frame = await render(
          "film",
          i / frameRate,
          view === "wide" ? "dolly" : view,
          896,
          504,
        );
        if (i === frameRate) {
          await save(view + ".jpg", frame);
          names.push(view + ".jpg");
        }
        yield Buffer.from(frame.jpeg, "base64");
      }
    }
    await encodeFilm(join(dir, view + ".mp4"), frameRate, frames());
    names.push(view + ".mp4");
    console.log(view, clipSeconds * frameRate, "frames");
  }
  for (const [name, t, view, w, h] of [
    ["cover", 1.04, "dolly", 1536, 960],
    ["arc", q.contact + 0.09, "wide", 1280, 760],
    ["hands", q.arrival, "patio", 1080, 608],
  ]) {
    await save(
      name + ".jpg",
      await render(name === "arc" ? "trace" : "film", t, view, w, h),
    );
    names.push(name + ".jpg");
  }
  for (const name of names)
    capture.files[name] = createHash("sha256")
      .update(await readFile(join(dir, name)))
      .digest("hex");
  await writeFile(
    join(dir, "capture.json"),
    JSON.stringify(capture, null, 2) + "\n",
  );
  for (const name of [...names, "capture.json"])
    await rename(join(dir, name), join("public/court", name));
}
