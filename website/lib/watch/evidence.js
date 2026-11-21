// The staged case for "someone unexpected is on the property": each item is a
// weight of evidence in millibans (thousandths of a ban, so +1000 multiplies
// the odds by ten). The weights are made up for the demonstration. Adding
// log-likelihood ratios is how the project's fusion crate combines evidence.
export const EVIDENCE = [
  { id: "prior", label: "How often a stranger is on this property at 02:14", mb: -2000, fixed: true },
  { id: "gate", label: "First camera: a person", mb: 1300 },
  { id: "drive", label: "Second camera: the same person on the same ground", mb: 1500 },
  { id: "shared", label: "Both cameras used the same detector, so they can fail together", mb: -600, needs: ["gate", "drive"] },
  { id: "lookout", label: "A second person standing at the gate", mb: 600 },
  { id: "cars", label: "Both household cars were already in the court", mb: 400 },
  { id: "lawn", label: "Approach across the grass, away from the path", mb: 500 },
  { id: "door", label: "A hand on the front door handle", mb: 900, late: true },
];

export const chance = (millibans) => 1 / (1 + 10 ** (-millibans / 1000));

/** The running sum at take time `t`, given when each item arrived. */
export function beliefAt(times, t) {
  let total = 0;
  for (const item of EVIDENCE) if ((times[item.id] ?? Infinity) <= t) total += item.mb;
  return total;
}
