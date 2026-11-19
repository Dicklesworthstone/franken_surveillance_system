// Titles are also used for accessible section links and the static share cards.
export const exhibits = {
  home: {
    title: "The home control room",
    lines: ["One home.", "Many views."],
    label: "Juniper House",
    description:
      "Follow an encounter through a home digital twin, three cameras and the evidence an agent can inspect.",
    caption: "JUNIPER HOUSE  /  INTERACTIVE FIELD GUIDE",
    color: "#cefa85",
  },
  "poster-room": {
    title: "The poster room",
    label: "Exhibit posters",
    lines: ["The poster", "room."],
    description:
      "Browse the gallery and download the Open Graph or X cover for each Juniper House exhibit.",
    caption: "EXHIBIT ARTWORK  /  FULL RESOLUTION",
    color: "#e6b783",
  },
  "stereo-bench": {
    title: "The stereo bench",
    label: "Stereo bench",
    lines: ["Two rays.", "One ball."],
    description:
      "Mark a basketball in two camera frames and locate it on the 3D court. Compare your estimate with a native FSS reconstruction.",
    caption: "TWO CAMERA RAYS  /  NATIVE POINT ESTIMATE",
    color: "#a1e4d8",
  },
  courtyard: {
    title: "The courtyard study",
    lines: ["The bounce", "pass."],
    label: "Courtyard",
    description:
      "Change a ball pass between two skinned 3D players, then compare motion-triggered watch results and native frame inspections from two cameras.",
    caption: "JUNIPER COURT  /  TWO PLAYERS IN MOTION",
    color: "#ffb48d",
  },
  "motion-study": {
    title: "Human motion study",
    lines: ["The parcel", "drop."],
    label: "Motion study",
    description:
      "Change the courier’s gait and the parcel’s bounce, then compare two camera views with native FSS measurements of the reference delivery.",
    caption: "JUNIPER HOUSE  /  HUMAN MOTION STUDY",
    color: "#ffb48d",
  },
  "digital-twin": {
    title: "The digital twin",
    lines: ["Inside", "Juniper House."],
    label: "Digital twin",
    description:
      "Orbit the property, look straight down at its layout and locate measured camera entries in the 3D survey.",
    caption: "METRIC SITE MODEL  /  THREE FIXED VIEWS",
    color: "#baf28b",
  },
  "camera-wall": {
    title: "The camera wall",
    lines: ["Four views.", "One instant."],
    label: "Camera wall",
    description:
      "Scrub three camera films and a moving 3D flyover together, one frame at a time.",
    caption: "MODEL + CAMERA FILMS  /  12 FRAMES PER SECOND",
    color: "#a9e2ee",
  },
  "camera-fusion": {
    title: "Camera fusion",
    lines: ["One entry,", "two angles."],
    label: "Camera fusion",
    description:
      "Compare two measured doorstep entries and discover why a quarter of a second changes the match.",
    caption: "DOORSTEP REPLAY  /  NATIVE ASSOCIATION",
    color: "#ffc68a",
  },
  "belief-lab": {
    title: "The belief lab",
    lines: ["A second", "opinion?"],
    label: "Belief lab",
    description:
      "Explore how two cameras sharing a source change an illustrative probability interval.",
    caption: "ILLUSTRATIVE PRESENCE HYPOTHESIS  /  FSS-FUSE",
    color: "#c4c0ff",
  },
  "event-ledger": {
    title: "The event ledger",
    lines: ["Change", "one byte."],
    label: "Event ledger",
    description:
      "Check the archived objects of a published event and see what happens when a single byte changes.",
    caption: "PUBLISHED EVENT  /  CONTENT-ADDRESSED OBJECTS",
    color: "#a8ecce",
  },
  "agent-console": {
    title: "The agent console",
    lines: ["Pass the", "case along."],
    label: "Agent console",
    description:
      "Inspect a real agent session from its first orientation through handoff and resume.",
    caption: "AGENT SESSION  /  NATIVE FSS RESPONSES",
    color: "#b0d7ff",
  },
  "owner-response": {
    title: "Owner-controlled response",
    lines: ["Before", "the alert."],
    label: "Owner response",
    description:
      "Read the native notification refusal and explore the design for owner-authorized actions.",
    caption: "NOTIFICATION PLANNING  /  DOORSTEP FIXTURE",
    color: "#ffbd81",
  },
  "camera-inputs": {
    title: "Camera inputs",
    lines: ["Bring your", "own camera."],
    label: "Camera inputs",
    description:
      "Explore how local streams, exported recordings and model-specific adapters fit into a home camera system.",
    caption: "RESIDENTIAL CAMERA  /  OPTICS CONCEPT",
    color: "#b6e7ca",
  },
  "film-archive": {
    title: "The film archive",
    lines: ["The night", "shift."],
    label: "Film archive",
    description:
      "Watch nine camera films across a doorstep delivery, a raccoon visit and an after-hours arrival.",
    caption: "JUNIPER HOUSE  /  SYNTHETIC CAMERA FILMS",
    color: "#fbcc9c",
  },
  "field-method": {
    title: "How to read the demo",
    lines: ["Scene or", "evidence?"],
    label: "Field method",
    description:
      "Trace the distinction between a scene label, a camera observation and a measured model result.",
    caption: "RENDERED SCENE  /  NATIVE MEASUREMENTS",
    color: "#c8e0ae",
  },
};
export const exhibitPath = (slug) =>
  slug === "home" ? "/" : "/exhibits/" + slug + "/";
