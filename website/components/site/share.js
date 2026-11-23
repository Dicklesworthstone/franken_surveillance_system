// Each chapter has a page of its own to share. Sites that show a preview read that page's title,
// description and picture; a visitor's browser goes straight on to the chapter on the home page.
// The folders under app/chapter/ carry these names, and scripts/make-share-cards.mjs draws their pictures.
export const SHARE = {
  minute: "the-minute",
  how: "one-picture",
  evidence: "the-evidence",
  watch: "the-agent",
  machine: "the-record",
};

export const sharePath = (id) => `/chapter/${SHARE[id]}/`;

/**
 * One sentence per chapter that makes sense on its own, away from the page: the share card's line
 * and the start of the preview's description. Each says what the chapter's thesis says.
 */
export const SHARE_LINE = {
  minute: "At 02:14 one man comes in through the gate while another keeps watch outside it.",
  how: "Cheap cameras disagree about the time and each sees one angle, so their streams go onto one clock and one model of the property.",
  evidence: "A camera that saw nobody and a camera that was blind are different facts.",
  watch: "An AI agent asks for the situation, gets a briefing sized to its budget, and may act only inside what you granted.",
  machine: "Every sighting, decision and action lands in one append-only record, held by one safe-Rust workspace.",
};
