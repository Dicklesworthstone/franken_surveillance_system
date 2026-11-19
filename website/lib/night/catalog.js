export const caseFiles = {
  "after-hours": {
    title: "The 02:14 intrusion report",
    localTime: "02:14",
    openingCamera: "entry",
    label: "Perimeter alert",
    description:
      "At 02:14 a resident reports an unfamiliar person at the closed entrance and a possible weapon. Review the approach from both sides of the walk.",
    report:
      "At 02:14 a resident reports an unfamiliar person approaching the house and says they may be armed. The cameras support a review of presence and movement. Weapon possession, identity and intent remain unresolved.",
  },
  delivery: {
    title: "The evening delivery",
    localTime: "20:37",
    openingCamera: "entry",
    label: "Doorstep activity",
    description:
      "Follow a courier carrying a parcel to the entrance and compare the approach with the late-night alert.",
    report:
      "The scene script describes a delivery. Only the recorded observations below come from the detector.",
  },
  wildlife: {
    title: "Movement in the garden",
    localTime: "01:08",
    openingCamera: "garden",
    label: "Wildlife review",
    description:
      "A raccoon moves across the grounds. Inspect which cameras picked up its movement and what the detector returned.",
    report:
      "The authored animal is a raccoon. The detector may name a different class or return no label for an inspected frame.",
  },
};
export const cases = Object.keys(caseFiles);
export const pathFor = (id) =>
  cases.includes(id)
    ? "/incidents/" + id + "/"
    : id === "home"
      ? "/"
      : "/exhibits/" + id + "/";
export const exhibits = {
  home: {
    title: "Who’s outside at 02:14?",
    label: "Overview",
    section: "home",
    description:
      "A resident reports a possible intruder at 02:14. Replay the approach across two cameras and trace the alert through the evidence ledger to the agent’s handoff.",
  },
  "digital-twin": {
    title: "The property in 3D",
    label: "Property twin",
    section: "twin",
    description:
      "Orbit the house in 3D or look through a mounted camera. Replay the approach and change the person’s height or walking pace.",
  },
  "camera-wall": {
    title: "The camera room",
    label: "Camera room",
    section: "replay",
    description:
      "Play the same encounter from the property’s fixed cameras on one timeline.",
  },
  "camera-fusion": {
    title: "Across two cameras",
    label: "Compare views",
    section: "compare",
    description:
      "Compare synchronized recordings and check the camera-specific observations from each viewpoint.",
  },
  "event-ledger": {
    title: "The evidence ledger",
    label: "Evidence ledger",
    section: "ledger",
    description:
      "Inspect the native event records and verify the bytes of the source camera recording.",
  },
  "agent-console": {
    title: "The agent desk",
    label: "Agent desk",
    section: "agent",
    description:
      "Inspect the case context and native records that an agent can use to answer a nighttime alert.",
  },
  "belief-lab": {
    title: "A report under review",
    label: "Hypotheses",
    section: "hypotheses",
    description:
      "Compare a resident’s report with the available camera evidence and inspect what remains unresolved.",
  },
  "owner-response": {
    title: "The response decision",
    label: "Response review",
    section: "response",
    description:
      "Read the native disposition for a recorded incident and the authority attached to it.",
  },
  "field-method": {
    title: "Inside a camera observation",
    label: "Frame evidence",
    section: "evidence",
    description:
      "Inspect the exact JPEG and the native model outputs for an observed instant.",
  },
  "camera-inputs": {
    title: "Camera sources",
    label: "Camera sources",
    section: "inputs",
    description:
      "Follow each synthetic camera source from its recorded film to its imported native frames.",
  },
  "film-archive": {
    title: "The incident archive",
    label: "Recordings",
    section: "archive",
    description:
      "Open the after-hours, delivery and wildlife films, all recorded on the same fictional property.",
  },
  "poster-room": {
    title: "The case files in print",
    label: "Exhibit prints",
    section: "prints",
    description:
      "Download covers made from the architectural renders and original camera recordings.",
  },
  // Established inbound links now open security exercises set on the same estate.
  "motion-study": {
    title: "Reconstruct the approach",
    label: "Movement study",
    section: "twin",
    description:
      "Change the human motion in a site reconstruction and compare it with the fixed reference films.",
  },
  "stereo-bench": {
    title: "Two views of the approach",
    label: "Sightline review",
    section: "compare",
    description:
      "Review an after-hours arrival from two calibrated locations on the same estate.",
  },
  courtyard: {
    title: "Perimeter incident review",
    label: "Perimeter review",
    section: "replay",
    description:
      "Follow a nighttime perimeter report from its recorded camera views into native evidence.",
  },
  ...Object.fromEntries(
    Object.entries(caseFiles).map(([id, c]) => [
      id,
      {
        title: c.title,
        label: c.label,
        description: c.description,
        section: "incident",
      },
    ]),
  ),
};
export const displayCamera = (id) =>
  id === "overview"
    ? "Site overview"
    : id.replaceAll(/[-_]/g, " ").replace(/^./, (c) => c.toUpperCase());
