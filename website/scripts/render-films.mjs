// Run from website/ with a local Chromium and FFmpeg installed.
import { build } from "esbuild";
import { chromium } from "playwright-core";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { once } from "node:events";
import { mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { imageToGround } from "../lib/cameras.js";
import {
  cameraAsset,
  cameras,
  cases,
  recording,
  DURATION,
} from "../lib/scenarios.js";

const bundle = await build({
  stdin: {
    contents: `
import { createProperty } from "./lib/property.js";
import { cases } from "./lib/scenarios.js";
const canvas = document.querySelector("canvas");
const stage = createProperty(canvas, false);
window.frame=(id,t,view,w,h)=>{
  if (canvas.width!==w || canvas.height!==h) stage.resize(w,h);const s=cases.find(s=>s.id===id);
  const result=stage.draw(s,t,view,true);
  return { jpeg:canvas.toDataURL("image/jpeg",.93).split(",")[1], visible:result.visible, inZone:result.inZone };
};`,
    resolveDir: process.cwd(),
  },
  bundle: true,
  write: false,
  minify: true,
});
const server = createServer((req, res) => {
  if (req.url === "/bundle.js") {
    res.setHeader("Content-Type", "text/javascript");
    res.end(bundle.outputFiles[0].contents);
  } else {
    res.setHeader("Content-Type", "text/html");
    res.end(
      '<!doctype html><canvas></canvas><script src="/bundle.js"></script>',
    );
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const browser = await chromium.launch({
  executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome",
  args: [
    "--no-sandbox",
    "--enable-unsafe-swiftshader",
    "--use-angle=swiftshader",
    "--disable-dev-shm-usage",
  ],
});
const stageDir = await mkdtemp(join(process.cwd(), ".render-"));
try {
  async function newRenderer() {
    const page = await browser.newPage();
    page.on("pageerror", (e) => console.error(e.message));
    page.on("console", (msg) => {
      if (msg.type() === "error") console.error(msg.text());
    });
    await page.goto("http://127.0.0.1:" + server.address().port);
    await page.waitForFunction(() => typeof window.frame === "function");
    return page;
  }
  let page = await newRenderer();
  const render = (id, t, view, w, h) =>
    page.evaluate((args) => window.frame(...args), [id, t, view, w, h]);
  // Render complete files before replacing the distributable fixtures.
  const outputs = [];
  const output = (name) => {
    outputs.push(name);
    return join(stageDir, name);
  };
  await writeFile(
    output("property.jpg"),
    Buffer.from(
      (await render("delivery", 4.8, "overview", 1240, 700)).jpeg,
      "base64",
    ),
  );
  const visibility = {};
  const rig = {
    duration: DURATION,
    recording,
    cameras: Object.fromEntries(
      cameras.map((c) => [
        c.id,
        {
          imageToGround: imageToGround(
            c,
            recording.nativeWidth,
            recording.nativeHeight,
          ),
        },
      ]),
    ),
    cases: {},
  };

  for (const s of cases) {
    const { fps, width: w, height: h } = recording;
    const [x, x1, z, z1] = s.zoneBounds;
    const views = {};
    rig.cases[s.id] = {
      primary: s.camera,
      zone: { id: s.id, rect: [x, z, x1 - x, z1 - z] },
      views,
    };
    for (const camera of cameras) {
      await page.close();
      page = await newRenderer();
      const stem = cameraAsset(s, camera.id);
      const proc = spawn(
        "ffmpeg",
        [
          "-hide_banner",
          "-loglevel",
          "error",
          "-y",
          "-f",
          "image2pipe",
          "-framerate",
          String(fps),
          "-vcodec",
          "mjpeg",
          "-i",
          "pipe:0",
          "-an",
          "-c:v",
          "libx264",
          "-threads",
          "2",
          "-preset",
          "fast",
          "-crf",
          "19",
          "-pix_fmt",
          "yuv420p",
          "-movflags",
          "+faststart",
          output(stem + ".mp4"),
        ],
        { stdio: ["pipe", "inherit", "inherit"] },
      );
      const done = once(proc, "close");
      const samples = [];
      async function* frames() {
        for (let n = 0; n < DURATION * fps; n++) {
          const t = n / fps,
            f = await render(s.id, t, camera.id, w, h);
          const jpg = Buffer.from(f.jpeg, "base64");
          if (n === fps * 6) await writeFile(output(stem + ".jpg"), jpg);
          if (
            !samples.length ||
            samples.at(-1).visible !== f.visible ||
            samples.at(-1).inZone !== f.inZone
          )
            samples.push({ time: t, visible: f.visible, inZone: f.inZone });
          yield jpg;
        }
      }
      try {
        const [[code]] = await Promise.all([
          done,
          pipeline(frames(), proc.stdin),
        ]);
        if (code !== 0) throw Error("FFmpeg failed for " + stem);
      } finally {
        if (proc.exitCode === null && proc.signalCode === null) {
          proc.stdin.destroy();
          proc.kill();
          await done;
        }
      }
      views[camera.id] = { asset: stem, visibility: samples };
      if (camera.id === s.camera) visibility[s.id] = samples;
      console.log(stem, samples.length, "visibility transitions");
    }
  }
  await writeFile(
    output("visibility.json"),
    JSON.stringify(visibility, null, 2) + "\n",
  );
  await writeFile(output("rig.json"), JSON.stringify(rig, null, 2) + "\n");
  for (const name of outputs)
    await rename(join(stageDir, name), join("public/films", name));
} finally {
  await rm(stageDir, { recursive: true, force: true });
  await browser.close();
  server.close();
}
