// Run from website/ with a local Chromium and FFmpeg installed.
import { build } from "esbuild";
import { chromium } from "playwright-core";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, writeFile } from "node:fs/promises";
import { cases, DURATION } from "../lib/scenarios.js";

const bundle = await build({
  stdin: {
    contents: `
import { createProperty } from "./lib/property.js";
import { cases } from "./lib/scenarios.js";
const canvas = document.querySelector("canvas");
const stage = createProperty(canvas, false);
window.frame=(id,t,view,w,h)=>{
  stage.resize(w,h);const s=cases.find(s=>s.id===id);
  const result=stage.draw(s,t,view==="camera"?s.camera:view,true);
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
try {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.error(e.message));
  page.on("console", (msg) => {
    if (msg.type() === "error") console.error(msg.text());
  });
  await page.goto("http://127.0.0.1:" + server.address().port);
  await page.waitForFunction(() => typeof window.frame === "function");
  const render = (id, t, view, w, h) =>
    page.evaluate((args) => window.frame(...args), [id, t, view, w, h]);
  await mkdir("public/films", { recursive: true });
  await writeFile(
    "public/films/property.jpg",
    Buffer.from(
      (await render("delivery", 4.8, "overview", 1240, 700)).jpeg,
      "base64",
    ),
  );
  const visibility = {};
  for (const s of cases) {
    const fps = 12,
      w = 768,
      h = 432;
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
        "public/films/" + s.id + ".mp4",
      ],
      { stdio: ["pipe", "inherit", "inherit"] },
    );
    const done = once(proc, "close");
    const samples = [];
    for (let n = 0; n < DURATION * fps; n++) {
      const t = n / fps,
        f = await render(s.id, t, "camera", w, h);
      const jpg = Buffer.from(f.jpeg, "base64");
      if (n === fps * 6) await writeFile("public/films/" + s.id + ".jpg", jpg);
      if (!proc.stdin.write(jpg)) await once(proc.stdin, "drain");
      if (
        !samples.length ||
        samples.at(-1).visible !== f.visible ||
        samples.at(-1).inZone !== f.inZone
      )
        samples.push({ time: t, visible: f.visible, inZone: f.inZone });
    }
    proc.stdin.end();
    if ((await done)[0] !== 0) throw Error("FFmpeg failed for " + s.id);
    visibility[s.id] = samples;
    console.log(s.id, JSON.stringify(samples));
  }
  await writeFile(
    "public/films/visibility.json",
    JSON.stringify(visibility, null, 2) + "\n",
  );
} finally {
  await browser.close();
  server.close();
}
