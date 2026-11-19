import { ImageResponse } from "next/og";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { cache } from "react";
import { cases, exhibits, displayCamera } from "./night/catalog";
import { nightData } from "./night/data";
const row = { display: "flex" },
  col = { display: "flex", flexDirection: "column" },
  abs = { position: "absolute", display: "flex" };
const fonts = cache(async () =>
  Promise.all(
    [
      [
        "Instrument",
        "normal",
        "@fontsource/instrument-serif/files/instrument-serif-latin-400-normal.woff",
      ],
      [
        "Instrument",
        "italic",
        "@fontsource/instrument-serif/files/instrument-serif-latin-400-italic.woff",
      ],
      [
        "Mono",
        "normal",
        "@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff",
      ],
    ].map(async ([name, style, file]) => ({
      name,
      style,
      weight: 400,
      data: await readFile(join(process.cwd(), "node_modules", file)),
    })),
  ),
);
const photograph = cache(async (url) => {
  const bytes = await readFile(join(process.cwd(), "public", url)),
    format = url.endsWith(".png") ? "png" : "jpeg";
  return "data:image/" + format + ";base64," + bytes.toString("base64");
});
const titles = {
  home: ["Alder House,", "after dark."],
  "after-hours": ["Intrusion report,", "02:14."],
  delivery: ["The evening", "delivery."],
  wildlife: ["Movement in", "the garden."],
  "digital-twin": ["The estate", "in 3D."],
  "camera-wall": ["The camera", "room."],
  "camera-fusion": ["Across two", "cameras."],
  "event-ledger": ["The evidence", "ledger."],
  "agent-console": ["The agent", "desk."],
  "belief-lab": ["A report", "under review."],
  "owner-response": ["The response", "decision."],
  "field-method": ["Inside an", "observation."],
  "camera-inputs": ["Camera", "sources."],
  "film-archive": ["The incident", "archive."],
  "poster-room": ["The estate", "in print."],
  "motion-study": ["Reconstruct", "the approach."],
  "stereo-bench": ["Two camera", "views."],
  courtyard: ["Perimeter", "review."],
};
const tag = (t, style = {}) => (
  <div
    style={{
      ...row,
      fontFamily: "Mono",
      fontSize: 15,
      letterSpacing: 1.3,
      ...style,
    }}
  >
    {t}
  </div>
);
const baseplate = (id, cam) => "/night-media/" + id + "-" + cam + ".jpg";
const render = cache(async (id, h) => {
  const data = nightData(),
    c = cases.includes(id)
      ? id
      : {
          "field-method": "wildlife",
          "camera-inputs": "delivery",
          "film-archive": "wildlife",
          "owner-response": "delivery",
        }[id] || "after-hours";
  const incident = data.records[c],
    cameras = Object.keys(incident.views),
    [head, ital] = titles[id];
  const cover = ["home", "digital-twin", "poster-room"].includes(id);
  const hero = data.estate.hero || "/estate/hero.jpg";
  const covers = {
    home: hero,
    "digital-twin": data.estate.photographs[0].url,
    "poster-room": data.estate.photographs[1].url,
  };
  const file = cover ? covers[id] : baseplate(c, incident.primary);
  const film = await photograph(file);
  const main = cover || cases.includes(id);
  const inset = main
    ? null
    : await photograph(
        baseplate(
          c,
          cameras.find((x) => x !== incident.primary) || incident.primary,
        ),
      );
  const typefaces = await fonts();
  const digest = createHash("sha256").update(
    JSON.stringify([
      id,
      h,
      titles[id],
      exhibits[id],
      incident.label,
      incident.primary,
      film,
      inset,
    ]),
  );
  for (const font of typefaces) digest.update(font.data);
  for (const file of ["lib/share-card.jsx", "lib/night/catalog.js", "bun.lock"])
    digest.update(await readFile(join(process.cwd(), file)));
  const directory = join(process.cwd(), ".next", "cache", "estate-covers");
  const cached = join(directory, digest.digest("hex") + ".png");
  try {
    return await readFile(cached);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const ink = main ? "#fff7e7" : "#223029",
    gold = main ? "#ebc78a" : "#815d37";
  const page = (
    <div
      style={{
        ...col,
        position: "relative",
        width: "100%",
        height: "100%",
        backgroundColor: main ? "#10201d" : "#eae6db",
        color: ink,
        fontFamily: "Instrument",
        overflow: "hidden",
      }}
    >
      {main ? (
        <>
          <img
            alt=""
            src={film}
            width={1200}
            height={h}
            style={{
              ...abs,
              top: 0,
              left: 0,
              width: 1200,
              height: h,
              objectFit: "cover",
            }}
          />
          <div
            style={{
              ...abs,
              left: 0,
              top: 0,
              width: 1200,
              height: h,
              backgroundImage:
                "linear-gradient(90deg,rgba(7,15,15,0.95),rgba(7,15,15,0.60) 54%,rgba(7,15,15,0.04))",
            }}
          />
        </>
      ) : (
        <>
          <img
            alt=""
            src={film}
            width={532}
            height={h - 90}
            style={{
              ...abs,
              left: 632,
              top: 45,
              width: 532,
              height: h - 90,
              objectFit: "cover",
            }}
          />
          <img
            alt=""
            src={inset}
            width={304}
            height={155}
            style={{
              ...abs,
              left: 580,
              top: h - 218,
              width: 304,
              height: 155,
              objectFit: "cover",
              border: "7px solid #eee9da",
            }}
          />
        </>
      )}
      <div
        style={{
          ...col,
          position: "relative",
          height: h,
          justifyContent: "space-between",
          padding: "44px 54px",
        }}
      >
        {tag("FRANKEN SURVEILLANCE", { color: main ? "#f1e1bd" : "#4e5c50" })}
        <div style={col}>
          {tag(
            cover
              ? "ALDER HOUSE  /  NIGHT WATCH"
              : incident.label.toUpperCase() +
                  "  /  " +
                  (main
                    ? displayCamera(incident.primary).toUpperCase()
                    : exhibits[id].label.toUpperCase()),
            { color: gold, marginBottom: 17 },
          )}
          <div
            style={{
              ...col,
              fontSize: main ? 112 : 92,
              lineHeight: 0.87,
              letterSpacing: -3.6,
            }}
          >
            <div style={row}>{head}</div>
            <div style={{ ...row, fontStyle: "italic", color: gold }}>
              {ital}
            </div>
          </div>
        </div>
        {tag("FRANKEN-SURVEILLANCE.COM", {
          fontSize: 13,
          color: main ? "#e2dccd" : "#687569",
        })}
      </div>
    </div>
  );
  const png = Buffer.from(
    await new ImageResponse(page, {
      width: 1200,
      height: h,
      fonts: typefaces,
    }).arrayBuffer(),
  );
  await mkdir(directory, { recursive: true });
  const temporary = cached + "." + randomUUID();
  await writeFile(temporary, png);
  await rename(temporary, cached);
  return png;
});
export async function imageMeta(id, h) {
  const bytes = await render(id, h);
  return [
    {
      id:
        createHash("sha256").update(bytes).digest("hex").slice(0, 20) + ".png",
      alt: exhibits[id].title + ". " + exhibits[id].description,
      size: { width: 1200, height: h },
      contentType: "image/png",
    },
  ];
}
export async function imageBody(id, h) {
  return new Response(await render(id, h), {
    headers: { "Content-Type": "image/png" },
  });
}
