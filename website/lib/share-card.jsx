import { ImageResponse } from "next/og";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { cache } from "react";
import { exhibits } from "./exhibits";
import { fieldData } from "./field-data";

const flex = { display: "flex" };
const column = { ...flex, flexDirection: "column" };
const mono = { ...flex, fontFamily: "Plex", fontSize: 19, letterSpacing: 1 };
const paper = "#e5eadb",
  ink = "#112321";
const local = (file) => readFile(path.join(process.cwd(), file));
const jpeg = async (file) =>
  "data:image/jpeg;base64," + (await local(file)).toString("base64");
const tag = (text, style = {}) => (
  <div style={{ ...mono, ...style }}>{text}</div>
);
function Photo({ src, width, height, style }) {
  return (
    <img
      alt=""
      src={src}
      width={width}
      height={height}
      style={{ ...flex, objectFit: "cover", ...style }}
    />
  );
}
function Band({ children, color }) {
  return (
    <div
      style={{
        ...mono,
        backgroundColor: color,
        color: ink,
        fontSize: 16,
        padding: "8px 12px",
        alignSelf: "flex-start",
      }}
    >
      {children}
    </div>
  );
}
function Mark({ color }) {
  return (
    <svg width="37" height="37" viewBox="0 0 40 40" fill="none">
      <circle cx="20" cy="20" r="17" stroke={color} strokeWidth="3" />
      <circle cx="20" cy="20" r="9" stroke={color} strokeWidth="2" />
      <circle cx="20" cy="20" r="3" fill={color} />
      <path
        d="M20 1V8M32 20H39M20 32V39M1 20H8"
        stroke={color}
        strokeWidth="2"
      />
    </svg>
  );
}
async function Plate({ slug, h, color }) {
  const panel = {
    ...column,
    position: "absolute",
    right: 0,
    top: 0,
    width: 586,
    height: h,
    overflow: "hidden",
    justifyContent: "center",
    alignItems: "center",
  };
  if (slug === "home")
    return (
      <Photo
        src={await jpeg("art/arrival.jpg")}
        width={1200}
        height={h}
        style={{ position: "absolute", top: 0, left: 0 }}
      />
    );
  if (["camera-inputs", "event-ledger", "digital-twin", "motion-study"].includes(slug)) {
    const file = {
      "camera-inputs": "art/camera-optics.jpg",
      "event-ledger": "art/ledger-glass.jpg",
      "digital-twin": "art/site-plan.jpg",
      "motion-study": "public/motion/pose.jpg",
    }[slug];
    return (
      <div style={panel}>
        <Photo src={await jpeg(file)} width={586} height={h} />
      </div>
    );
  }
  if (slug === "camera-wall")
    return (
      <div style={{ ...panel, backgroundColor: "#183032" }}>
        <div
          style={{
            ...column,
            width: 552,
            padding: 10,
            backgroundColor: "#0a171b",
            border: "1px solid #567877",
            transform: "rotate(-4deg)",
          }}
        >
          <Band color={color}>SYNCHRONIZED QUAD</Band>
          <Photo
            src={await jpeg("public/wall/delivery.jpg")}
            width={530}
            height={299}
          />
          {tag("12 FPS     /     JUNIPER HOUSE", {
            color,
            fontSize: 14,
            paddingTop: 8,
          })}
        </div>
      </div>
    );
  if (["camera-fusion", "film-archive", "field-method"].includes(slug)) {
    const strips = {
      "camera-fusion": [
        ["public/field/porch.jpg", "PORCH  /  ENTRY"],
        ["public/field/drive.jpg", "DRIVEWAY  /  ENTRY"],
      ],
      "film-archive": [
        ["public/films/delivery.jpg", "17:42  /  PORCH"],
        ["public/films/wildlife.jpg", "21:16  /  GARDEN"],
        ["public/films/visitor.jpg", "23:08  /  DRIVEWAY"],
      ],
      "field-method": [
        ["public/films/property.jpg", "SCENE GEOMETRY"],
        ["public/field/porch.jpg", "SOURCE FRAME"],
      ],
    }[slug];
    return (
      <div style={{ ...panel, backgroundColor: "#112322", gap: 8 }}>
        {await Promise.all(
          strips.map(async ([src, label]) => (
            <div
              key={label}
              style={{
                ...flex,
                position: "relative",
                overflow: "hidden",
                width: 540,
                height: strips.length === 3 ? 165 : 236,
              }}
            >
              <Photo
                src={await jpeg(src)}
                width={540}
                height={strips.length === 3 ? 165 : 236}
              />
              <div
                style={{
                  ...mono,
                  position: "absolute",
                  left: 8,
                  bottom: 8,
                  backgroundColor: ink,
                  padding: "5px 9px",
                  color,
                  fontSize: 15,
                }}
              >
                {label}
              </div>
            </div>
          )),
        )}
      </div>
    );
  }
  const field = fieldData();
  if (slug === "belief-lab")
    return (
      <div
        style={{
          ...panel,
          backgroundColor: "#292b42",
          padding: 34,
          alignItems: "stretch",
        }}
      >
        <Band color={color}>PRESENCE INTERVAL</Band>
        {["single", "shared", "independent"].map((key, i) => {
          const [lo, hi] = field.belief[key].interval.map((v) => v / 10000);
          return (
            <div key={key} style={{ ...column, marginTop: 36, color: "#fff" }}>
              <div style={{ ...flex, justifyContent: "space-between" }}>
                {tag(["ONE CAMERA", "SHARED SOURCE", "INDEPENDENT"][i], {
                  fontSize: 16,
                })}
                {tag(lo.toFixed(1) + " — " + hi.toFixed(1) + "%", {
                  fontSize: 17,
                  color,
                })}
              </div>
              <div
                style={{
                  ...flex,
                  position: "relative",
                  height: 19,
                  backgroundColor: "#45465d",
                  marginTop: 10,
                }}
              >
                <div
                  style={{
                    ...flex,
                    position: "absolute",
                    left: lo + "%",
                    width: hi - lo + "%",
                    height: 19,
                    backgroundColor: color,
                  }}
                />
              </div>
            </div>
          );
        })}
        <div
          style={{
            ...flex,
            justifyContent: "space-between",
            color: "#a5a9c0",
            marginTop: 12,
          }}
        >
          {tag("0%", { fontSize: 13 })}
          {tag("100%", { fontSize: 13 })}
        </div>
      </div>
    );
  const held = slug === "owner-response";
  const ops = held ? ["explain", "alert"] : ["orient", "handoff", "resume"];
  return (
    <div
      style={{
        ...panel,
        backgroundColor: held ? "#36291f" : "#202f37",
        padding: 34,
      }}
    >
      <div
        style={{
          ...column,
          backgroundColor: paper,
          padding: "28px 26px",
          width: 490,
          color: ink,
          transform: held ? "rotate(-4deg)" : "rotate(3deg)",
          borderTop: "9px solid " + color,
        }}
      >
        {tag("JUNIPER HOUSE   /   FSS/1", { fontSize: 17 })}
        <div
          style={{
            ...flex,
            fontSize: held ? 75 : 53,
            letterSpacing: -3,
            marginTop: 24,
            marginBottom: 14,
          }}
        >
          {held ? "Alert held." : "Case handoff."}
        </div>
        {ops.map((key) => (
          <div
            key={key}
            style={{
              ...flex,
              padding: "18px 0",
              borderTop: "1px solid #a6b1a5",
              justifyContent: "space-between",
            }}
          >
            {tag(key.toUpperCase(), { fontSize: 19 })}
            {tag(field.agent[key].outcome.toUpperCase(), { fontSize: 19 })}
          </div>
        ))}
        {tag(held ? field.agent.alert.error : "SESSION SCOPE RETAINED", {
          fontSize: 15,
          borderTop: "1px solid #a6b1a5",
          paddingTop: 20,
        })}
      </div>
    </div>
  );
}

const raster = cache(async (slug, height) => {
  const info = exhibits[slug],
    { color } = info;
  const light = ["camera-fusion", "film-archive", "field-method"].includes(
    slug,
  );
  const fg = light ? ink : paper,
    accent = light ? "#445e41" : color;
  const fonts = await Promise.all([
    local("node_modules/next/dist/compiled/@vercel/og/Geist-Regular.ttf"),
    local(
      "node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff",
    ),
  ]);
  const content = (
    <div
      style={{
        ...flex,
        width: 1200,
        height,
        position: "relative",
        overflow: "hidden",
        fontFamily: "Geist",
        backgroundColor: light ? paper : ink,
        color: fg,
      }}
    >
      {await Plate({ slug, h: height, color })}
      {slug === "home" && (
        <div
          style={{
            ...flex,
            position: "absolute",
            inset: 0,
            width: 1200,
            height,
            backgroundImage:
              "linear-gradient(90deg, rgba(5,18,17,0.99) 0%, rgba(5,18,17,0.84) 35%, rgba(5,18,17,0.02) 76%)",
          }}
        />
      )}
      <div
        style={{
          ...column,
          position: "absolute",
          left: 45,
          top: 35,
          width: 554,
          height: height - 70,
          justifyContent: "space-between",
        }}
      >
        <div style={{ ...flex, gap: 13, alignItems: "center" }}>
          <Mark color={accent} />
          <div style={{ ...flex, fontSize: 29, letterSpacing: -1.4 }}>
            Franken Surveillance
          </div>
        </div>
        <div style={{ ...column }}>
          {tag(info.label.toUpperCase(), {
            color: accent,
            fontSize: 20,
            marginBottom: 24,
          })}
          {info.lines.map((line, i) => (
            <div
              key={line}
              style={{
                ...flex,
                fontSize: 86,
                lineHeight: 1.02,
                letterSpacing: -6,
                color: i ? accent : fg,
              }}
            >
              {line}
            </div>
          ))}
        </div>
        <div style={{ ...column, gap: 13 }}>
          <div
            style={{ ...flex, width: 70, height: 3, backgroundColor: accent }}
          />
          {tag(info.caption, { fontSize: 14, color: fg, letterSpacing: 0.5 })}
        </div>
      </div>
    </div>
  );
  const response = new ImageResponse(content, {
    width: 1200,
    height,
    fonts: [
      { name: "Geist", data: fonts[0], weight: 400 },
      { name: "Plex", data: fonts[1], weight: 400 },
    ],
  });
  return Buffer.from(await response.arrayBuffer());
});

// A real .png suffix survives a static host's MIME detection; the bytes name
// their own URL, including when only a fixture, font or composition changes.
export async function imageMeta(slug, height) {
  const bytes = await raster(slug, height);
  return [
    {
      id:
        createHash("sha256").update(bytes).digest("hex").slice(0, 20) + ".png",
      alt: exhibits[slug].title + ". " + exhibits[slug].description,
      size: { width: 1200, height },
      contentType: "image/png",
    },
  ];
}
export async function imageBody(slug, height) {
  return new Response(await raster(slug, height), {
    headers: { "Content-Type": "image/png" },
  });
}
