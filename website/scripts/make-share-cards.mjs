// Draws the two pictures other sites show for a link to this one, app/opengraph-image.jpg and
// app/twitter-image.jpg, from one still of the scene and the page's own type and colours.
// Their alt text is in the .alt.txt beside each; keep it true of the picture.
//
//   node scripts/make-share-cards.mjs
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const file = (path) => fileURLToPath(new URL("../" + path, import.meta.url));
const data = async (path, type) => `data:${type};base64,${(await readFile(file(path))).toString("base64")}`;
const tokens = await readFile(file("app/styles/tokens.css"), "utf8");
const font = await data("node_modules/@fontsource-variable/inter/files/inter-latin-opsz-normal.woff2", "font/woff2");
const mono = await data("node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2", "font/woff2");
const still = await data("public/watch/intrusion/stills/floods.jpg", "image/jpeg");
const mark = await data("app/icon.svg", "image/svg+xml");

const html = `<!doctype html><meta charset="utf-8"><style>
${tokens}
@font-face { font-family: "Card"; src: url(${font}); font-weight: 100 900; }
@font-face { font-family: "Card Mono"; src: url(${mono}); font-weight: 100 800; }
* { box-sizing: border-box; margin: 0; }
body { position: relative; width: 100vw; height: 100vh; overflow: hidden; background: var(--ink); color: #fff; font-family: "Card"; font-optical-sizing: auto; }
.still { position: absolute; inset: 0 0 0 auto; width: 86%; height: 100%; object-fit: cover; object-position: 60% 46%; }
.ground { position: absolute; inset: 0; background:
  radial-gradient(640px 420px at 4% 8%, rgb(255 194 77 / .13), transparent 66%),
  linear-gradient(to right, var(--ink) 14%, rgb(5 7 11 / .88) 27%, rgb(5 7 11 / .34) 52%, transparent 70%),
  linear-gradient(to top, rgb(5 7 11 / .86), transparent 40%); }
.brand { position: absolute; left: 64px; top: 56px; display: flex; align-items: center; gap: 16px; font-size: 27px; font-weight: 800; letter-spacing: -.03em; }
.brand img { width: 42px; height: 42px; filter: drop-shadow(0 0 14px rgb(255 194 77 / .5)); }
h1 { position: absolute; left: 60px; bottom: 60px; width: 680px; font-size: 84px; font-weight: 800; line-height: .97; letter-spacing: -.052em; }
h1 span { color: var(--lamp); }
p { position: absolute; right: 66px; bottom: 40px; font: 500 17px "Card Mono"; color: rgb(255 255 255 / .72); }
i { position: absolute; width: 22px; height: 22px; border: 0 solid rgb(255 255 255 / .55); }
</style>
<img class="still" src="${still}" alt=""><div class="ground"></div>
<i style="left:28px;top:28px;border-width:2px 0 0 2px"></i><i style="right:28px;top:28px;border-width:2px 2px 0 0"></i>
<i style="left:28px;bottom:28px;border-width:0 0 2px 2px"></i><i style="right:28px;bottom:28px;border-width:0 2px 2px 0"></i>
<div class="brand"><img src="${mark}" alt="">Franken Surveillance</div>
<h1>A security room for your house, built from <span>$35 cameras</span>.</h1>
<p>Rendered scene, fictional house</p>`;

const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
try {
  for (const [name, height] of [["opengraph-image", 630], ["twitter-image", 600]]) {
    const page = await browser.newPage({ viewport: { width: 1200, height } });
    await page.setContent(html, { waitUntil: "load" });
    await page.evaluate(() => Promise.all([document.fonts.ready, ...[...document.images].map((image) => image.decode())]));
    await page.screenshot({ path: file(`app/${name}.jpg`), type: "jpeg", quality: 88 });
    await page.close();
    console.log(name, "1200 by", height);
  }
} finally {
  await browser.close();
}
