// The staged account of the take: what the agent was told, what it called and
// what was written down. Times come from the take's own beats and sightings, so
// the account follows the film. Nothing here is output of the FSS binaries;
// the page marks it as staged.
import { EVIDENCE, beliefAt, chance } from "./evidence.js";
import { CLOSE_AFTER, frameAt, seenBy, sightings, stamp } from "./take.js";

const OPS = {
  open: ["AOP-001", "session.open"],
  orient: ["AOP-003", "session.orient"],
  follow: ["AOP-004", "session.follow"],
  investigate: ["AOP-006", "investigate"],
  plan: ["AOP-007", "plan"],
  commit: ["AOP-008", "commit"],
  wait: ["AOP-009", "wait"],
  handoff: ["AOP-012", "handoff"],
};

function longestGap(take, actor) {
  let best = null;
  let open = null;
  let seen = false;
  for (let f = 0; f < take.frames; f++) {
    if (take.tracks[actor]?.x[f] == null) continue;
    const visible = seenBy(take, actor, f).length > 0;
    if (visible) {
      if (open !== null && (!best || f - open > best.frames))
        best = { from: open / take.fps, to: f / take.fps, frames: f - open };
      open = null;
      seen = true;
    } else if (seen && open === null) open = f;
  }
  return best && best.frames >= take.fps ? best : null;
}

export function buildStory(take) {
  const b = take.beats;
  const spans = sightings(take);
  const name = (id) => take.cameras.find((c) => c.id === id)?.name ?? id;
  // T1 is the first actor, so the lines about T1's first sighting use that actor's own spans.
  const own = spans.filter((span) => span.actor === "a");
  const first = (own.length ? own : spans).reduce((a, s) => (s.from < a.from ? s : a));
  // The first moment two cameras hold the same person for half a second. A single
  // frame of overlap is not counted: the console would not show it either.
  let corroborated = null;
  for (let f = 0, run = 0; f < take.frames && !corroborated; f++) {
    run = seenBy(take, "a", f).length > 1 ? run + 1 : 0;
    if (run >= take.fps / 2) {
      const start = f - run + 1;
      corroborated = { t: start / take.fps, cameras: seenBy(take, "a", start) };
    }
  }
  corroborated ??= { t: first.from + 3, cameras: [first.camera] };
  // When each person was last in view of any camera.
  const lastSeen = (actor) => Math.max(0, ...spans.filter((span) => span.actor === actor).map((span) => span.to));
  const goneA = Math.max(b.a_exits_gate ?? 0, lastSeen("a"));
  const goneB = lastSeen("b");
  const gap = longestGap(take, "a");
  const pair = corroborated.cameras.slice(0, 2).map(name).join(" and ");
  const at = (t) => Math.max(0, Math.min(take.duration - 0.1, t));
  // Whether any camera still has the second person when the agent reports both of them running.
  const flight = at(b.a_turns_to_run + 1.6);
  const lookoutInView = seenBy(take, "b", frameAt(take, flight)).length > 0;
  // A moment at which a tracked person is in no camera's view, for the walk-through step on coverage.
  const unseen = gap
    ? { t: gap.from + 0.5, moment: "No camera can see the person" }
    : goneB > 0 && goneB + 1 < take.duration
      ? { t: goneB + 1, moment: "The second person leaves every camera's view" }
      : null;

  const agent = [
    {
      t: 0,
      op: "open",
      line: "Night session opened. Granted: read every camera, alert the owner, switch the exterior lights between 23:00 and 06:00. The siren and the gate need the owner's tap.",
    },
    {
      t: at(first.from + 1.1),
      op: "follow",
      line: `Track T1 confirmed on the ${name(first.camera).toLowerCase()} camera after five observations across one second. One camera, so the evidence class is observed.`,
    },
    {
      t: at(corroborated.t + 0.4),
      op: "follow",
      line: `T1 corroborated. The ${pair.toLowerCase()} cameras place the same person on the ground within half a metre of each other. T2 confirmed and standing still on the pavement beside the gate pier.`,
    },
    {
      t: at(corroborated.t + 1.8),
      op: "orient",
      line: "Briefing, under 1,600 tokens: one adult inside the gate at 02:14 and a second waiting outside it, nobody expected, both household cars already in the court.",
    },
    {
      t: at(b.a_leaves_drive + 0.6),
      op: "follow",
      line: gap
        ? `T1 has left the drive and is crossing the lawn, away from the path lights. No camera covered ${gap.frames / take.fps < 10 ? (gap.to - gap.from).toFixed(1) : Math.round(gap.to - gap.from)} s of the crossing; the position is held as estimated, with a growing bound, and is not reported as empty lawn.`
        : "T1 has left the drive and is crossing the lawn toward the front door, away from the path lights.",
    },
    {
      t: at(b.a_leaves_drive + 2.2),
      op: "investigate",
      line: "Case opened with four explanations: resident, expected visitor, delivery, intruder. A lookout at the gate and an approach across the grass count against the first two. The hour counts against a delivery.",
    },
    {
      t: at(b.a_leaves_drive + 3.8),
      op: "plan",
      line: "Five options came back. Keep watching and alert the owner are both safe in every reading of the scene. Lights are allowed once a corroborated person is near the house. The siren is blocked until the owner approves. Calling the police is not available.",
    },
    {
      t: at(b.a_leaves_drive + 5),
      op: "commit",
      effect: "alert",
      line: "Owner alert sent with the clearest frame so far attached. The relay accepted it. Whether the owner has read it is unknown.",
    },
    {
      t: at(b.a_tries_door + 1),
      op: "follow",
      line: "T1 is at the front door with a hand on the handle, seen by the doorbell at under a metre.",
    },
    {
      t: at(b.lights_on - 0.5),
      op: "commit",
      effect: "lights",
      line: "Exterior lights committed under the night grant. The plan digest matched, the grant was still valid and the person was still corroborated at commit time.",
    },
    {
      t: at(b.lights_on + 0.9),
      op: "wait",
      line: "Checked against the cameras: brightness rose on the driveway, porch and lawn views within half a second. Effect outcome: verified.",
    },
    {
      t: flight,
      op: "follow",
      // Nothing is said about where a person is once no camera has them.
      line: lookoutInView
        ? "T1 is running away from the house. T2 has left the gate pier and is running along the street."
        : "T1 is running away from the house. T2 ran from the gate pier and out of the gate camera's view. Where T2 went is not observable.",
    },
    {
      t: at(goneA + 0.4),
      op: "follow",
      line: "T1 is out through the gate and out of every camera's view. The street beyond the wall is outside coverage, so the track is held as not observable. Where they went is recorded as unknown.",
    },
    {
      t: at(b.gate_starts_closing - 0.8),
      op: "commit",
      effect: "gate",
      line: "The owner approved closing the gate from the alert. Committed once no track was within the swing of the leaves.",
    },
    {
      t: at(b.gate_closed + 0.5),
      op: "wait",
      line: "The gate camera shows both leaves shut. Effect outcome: verified.",
    },
    {
      t: at(take.duration - 2.5),
      op: "handoff",
      // The owner answered the alert when they approved the gate, so its read state is no longer open.
      line: "Handoff written for whoever picks this up next: what happened, what is still unknown (who they were, where they went) and one open obligation: send the owner the outcome.",
    },
  ]
    // The lists that follow the clock rely on rows being in time order, whatever the take's beats are.
    .sort((x, y) => x.t - y.t)
    .map((e, i) => ({
      ...e,
      id: "agent-" + i,
      opId: OPS[e.op][0],
      opName: OPS[e.op][1],
      clock: stamp(take, e.t),
    }));

  const ledger = [
    [first.from + 0.2, "observation", `Motion candidate, ${name(first.camera).toLowerCase()} camera`],
    [first.from + 1.1, "track.confirmed", "T1, class person, evidence observed"],
    [corroborated.t + 0.3, "event.corroborated", `E1 raised by T1, ${pair.toLowerCase()}`],
    [corroborated.t + 0.4, "track.confirmed", "T2, class person, stationary"],
    gap && [gap.from + 0.2, "coverage", "T1 not_observable, held as estimated"],
    [b.a_leaves_drive + 2.2, "case.opened", "Four explanations, none closed"],
    [b.a_leaves_drive + 3.8, "plan.prepared", "Owner alert, bound to the situation digest"],
    [b.a_leaves_drive + 5, "effect.committed", "Owner alert dispatched"],
    [b.a_leaves_drive + 5.6, "effect.observed", "Relay accepted, read state unknown"],
    [b.lights_on - 0.5, "effect.committed", "Exterior lights, standing night grant"],
    [b.lights_on + 0.9, "effect.verified", "Lights seen on by three cameras"],
    goneB > 0 && goneB + 0.2 < take.duration && [goneB + 0.2, "coverage", "T2 not_observable, last seen from the gate"],
    goneB > 0 && goneB + CLOSE_AFTER < take.duration && [goneB + CLOSE_AFTER, "track.closed", `T2, no sighting for ${CLOSE_AFTER} s`],
    [goneA + 0.4, "coverage", "T1 not_observable, left coverage at the gate"],
    [b.gate_starts_closing - 0.8, "effect.committed", "Gate close, approved by the owner"],
    [b.gate_closed + 0.5, "effect.verified", "Gate seen shut"],
    [take.duration - 2.5, "handoff.published", "One obligation open"],
  ]
    .filter(Boolean)
    .map(([t, kind, subject]) => ({ t: at(t), kind, subject }))
    // Sequence numbers are given in time order.
    .sort((x, y) => x.t - y.t)
    .map((row, i) => ({ id: "row-" + i, seq: i + 1, clock: stamp(take, row.t, 0, true), ...row }));

  const markers = [
    [first.from, "First sighting"],
    [corroborated.t, "Two cameras agree"],
    [b.a_leaves_drive, "Leaves the drive"],
    [b.a_leaves_drive + 5, "Owner alerted"],
    [b.a_tries_door, "Tries the door"],
    [b.lights_on, "Lights on"],
    [b.a_exits_gate, "Out of the gate"],
    [b.gate_closed, "Gate shut"],
  ].map(([t, label], i) => ({ id: "mark-" + i, t: at(t), label, clock: stamp(take, at(t)) }));

  // When each item of the staged case arrives.
  const evidence = {
    prior: 0,
    gate: at(first.from + 1.1),
    drive: at(corroborated.t + 0.4),
    shared: at(corroborated.t + 0.4),
    lookout: at(Math.max(b.b_stops_at_pier + 3, corroborated.t + 0.4)),
    cars: at(corroborated.t + 1.8),
    lawn: at(b.a_leaves_drive + 0.6),
    door: at(b.a_tries_door + 1),
  };
  const steps = [...new Set(Object.values(evidence))].sort((x, y) => x - y);
  const belief = steps.map((t, i) => {
    const total = beliefAt(evidence, t);
    const latest = EVIDENCE.filter((item) => evidence[item.id] === t).at(-1);
    return { from: t, to: steps[i + 1] ?? take.duration, millibans: total, chance: chance(total), latest: latest.label };
  });

  // The instant at which the most cameras have someone in view, for showing all five side by side.
  let together = { t: corroborated.t, score: 0 };
  for (let f = 0; f < take.frames; f += 3) {
    const score = seenBy(take, "a", f).length + 0.4 * seenBy(take, "b", f).length;
    if (score > together.score) together = { t: f / take.fps, score };
  }

  return { agent, ledger, markers, gap, unseen, corroborated, first, evidence, belief, together: together.t };
}
