// The page's five chapters. Each wears one kind of light a night camera has to deal with.
// `plate` names the pictures in public/watch/plates made by scripts/make-plates.mjs, and
// `plateWidths` the widths they come in where their source is too small for the usual three.
export const CHAPTERS = [
  {
    id: "minute",
    number: "01",
    label: "The minute",
    short: "Minute",
    light: "sodium",
    plate: "gate",
    title: "One minute, [five cameras].",
    thesis:
      "At 02:14 one man comes in through the gate while another keeps watch outside it. The films, the site model, the agent and the ledger all run off one clock. Press play, step between moments or drag the timeline.",
    sections: [["console", "The replay"]],
  },
  {
    id: "how",
    number: "02",
    label: "One picture",
    short: "Picture",
    light: "moon",
    plate: "lawn",
    title: "Every camera, [one picture].",
    thesis:
      "Cheap cameras disagree about the time and each sees one angle. Their streams go onto one record first. Then every sighting goes onto one model of the property, where a person is counted once.",
    sections: [
      ["inputs", "Five makers, five clocks"],
      ["fusion", "One person, counted once"],
    ],
  },
  {
    id: "evidence",
    number: "03",
    label: "The evidence",
    short: "Evidence",
    light: "infrared",
    plate: "drive",
    title: "Seen, unseen and [how sure].",
    thesis:
      "A camera that saw nobody and a camera that was blind are different facts. The record keeps them apart, and any conclusion can be taken back down to the sightings it was made from.",
    sections: [
      ["coverage", "What it cannot see"],
      ["delivery-dropout", "The missing two seconds"],
      ["belief", "A probability in pieces"],
    ],
  },
  {
    id: "watch",
    number: "04",
    label: "The agent",
    short: "Agent",
    light: "phosphor",
    plate: "door",
    title: "An agent on the [night shift].",
    thesis:
      "Nobody should have to watch five video streams all night, and that includes an AI agent. It asks for the situation, gets a briefing sized to its budget, and may act only inside what you granted.",
    sections: [
      ["agent", "A briefing with a budget"],
      ["effects", "Acting inside its grants"],
    ],
  },
  {
    id: "machine",
    number: "05",
    label: "The record",
    short: "Record",
    light: "dawn",
    plate: "dusk",
    plateWidths: [960, 1600, 1920],
    title: "Written down [once], and kept.",
    thesis:
      "Everything above lands in one append-only record, held by one safe-Rust workspace. The chapter closes with the plainest list on the page: what runs today, what is built but unproven, and what is planned.",
    sections: [
      ["record", "Every byte has a fingerprint"],
      ["architecture", "Planes and the membrane"],
      ["status", "What runs today"],
    ],
  },
];

/** "03.2", from a section's place in its chapter. */
export function sectionIndex(id) {
  for (const chapter of CHAPTERS) {
    const at = chapter.sections.findIndex(([section]) => section === id);
    if (at >= 0) return `${chapter.number}.${at + 1}`;
  }
  throw Error("No chapter lists the section " + id);
}
