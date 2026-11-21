// Reduces native.json, the output of the project's own binaries run on the
// take's film files, to the facts the page prints. Everything returned here is
// measured. Knowledge states and refusals pass through as the tools gave them.

const VIEWS = {
  "AVIEW-001": "pulse",
  "AVIEW-002": "brief",
  "AVIEW-003": "case",
  "AVIEW-004": "forensic",
  "AVIEW-005": "operation",
  "AVIEW-006": "handoff",
  "AVIEW-007": "decision_diff",
  "AVIEW-008": "epistemic_map",
};

const REASONS = {
  "ERR-AGENT-CONTEXT-INCOMPLETE-001": "the critical facts do not fit in this view's token limit",
  "ERR-ALERT-NOT-ELIGIBLE-001": "an event seen by one camera cannot raise an alert",
  "ERR-OP-TIMEOUT-001": "no proof of delivery arrived before the deadline",
  "ERR-OP-PRECONDITION-FAILED-001": "the plan cannot close before its outcome is reconciled",
  "ERR-WATCH-LIMIT-001": "the watch reached its work limit",
  "ERR-CLI-RUNTIME-FAILURE-001": "the command stopped with a runtime failure",
  "ERR-DECODE-SOURCE-UNAVAILABLE-001": "the stored film could not be read back in time",
};
const BANDS = [
  ["over_20_percent", "More than 20%"],
  ["8_to_20_percent", "8% to 20%"],
  ["5_to_8_percent", "5% to 8%"],
];
// The comparison rule the page describes in words. If the driver's rule changes, the page prints it verbatim.
const KNOWN_RULE = /visibility >= 0\.25 and box height >= 0\.05 of the frame; a person detection matches at IoU >= 0\.3/;

const range = (values) => (values.length ? [Math.min(...values), Math.max(...values)] : null);

function candidates(side) {
  const list = side?.candidates ?? [];
  // Every distinct state and action the tool gave its matches, most common first.
  const kinds = new Map();
  for (const c of list) {
    const key = c.event_state + "|" + c.policy_action;
    const seen = kinds.get(key);
    if (seen) seen.count += 1;
    else kinds.set(key, { state: c.event_state ?? null, action: c.policy_action ?? null, count: 1 });
  }
  return {
    // "ok" when the tool ran under this declaration. Any other outcome is kept with its reason.
    outcome: side?.outcome ?? null,
    reason: side?.reason ?? null,
    count: list.length,
    outcomes: [...kinds.values()].sort((a, b) => b.count - a.count),
    // null when the tool gave no figure, which is not the same as zero.
    residual: range(list.map((c) => c.residual_m).filter((v) => v != null)),
    lag: range(list.map((c) => c.time_difference_s).filter((v) => v != null)),
    list: list.map((c) => ({
      t: Array.isArray(c.t) ? (c.t[0] + c.t[1]) / 2 : c.t,
      // When each of the two cameras made its observation.
      times: Array.isArray(c.t) ? c.t : [c.t],
      eventId: c.event_id,
      retainedDistance: c.nearest_scripted_person?.distance_m ?? null,
      ground: c.ground,
      residual: c.residual_m,
      lag: c.time_difference_s,
    })),
  };
}

const overlap = (a, b) => {
  const w = Math.min(a[2], b[2]) - Math.max(a[0], b[0]);
  const h = Math.min(a[3], b[3]) - Math.max(a[1], b[1]);
  if (w <= 0 || h <= 0) return 0;
  const area = (r) => (r[2] - r[0]) * (r[3] - r[1]);
  return (w * h) / (area(a) + area(b) - w * h);
};

/**
 * Places where the detector kept putting a person box on something that does
 * not move. The driver reports clusters of near-identical boxes; two clusters
 * that overlap are the same place, so they are merged here.
 */
function fixedSpots(clusters) {
  const spots = [];
  for (const cluster of clusters ?? []) {
    const same = spots.find((spot) => overlap(spot.box, cluster.box) >= 0.3);
    if (same) same.boxes += cluster.frames;
    else spots.push({ box: cluster.box, boxes: cluster.frames });
  }
  return spots;
}

export function distill(native) {
  if (!native) return null;
  const cameras = Object.entries(native.cameras).map(([id, c]) => ({
    id,
    rectilinear: c.rectilinear,
    sha256: c.custody.outcome === "ok" ? c.custody.sha256.replace(/^sha256:/, "") : null,
    bytes: c.custody.bytes ?? null,
    frames: c.custody.frames ?? null,
    seconds: c.custody.duration_seconds ?? (c.custody.frames != null && c.custody.fps > 0 ? c.custody.frames / c.custody.fps : null),
    custodyReason: c.custody.reason ?? c.custody.refusal ?? null,
    codec: c.custody.codec,
    custody: c.custody.outcome,
    captureTime: c.custody.capture_time_class,
    // null means the step did not produce a count; the refusal says why.
    motion: c.motion?.outcome === "refused" ? null : (c.motion?.candidate_count ?? null),
    motionRefusal: c.motion?.outcome === "refused" ? (REASONS[c.motion.refusal] ?? c.motion.refusal) : null,
    coverage: c.coverage
      ? {
          outcome: c.coverage.outcome,
          report: c.coverage.reports?.[0] ? `/watch/${native.take}/${c.coverage.reports[0]}` : null,
          records: c.coverage.witness_count ?? null,
          seconds: c.coverage.covered_seconds ?? null,
          // The tool's own flag from its retained coverage reports: whether absence is certified
          // inside the records. null when no report states it.
          certified: c.coverage.absence_certified_for_witness_domains ?? null,
          refusal:
            c.coverage.outcome === "refused"
              ? (REASONS[c.coverage.refusal] ??
                c.coverage.refusal ??
                REASONS[c.coverage.windows_failed?.[0]?.refusal] ??
                c.coverage.windows_failed?.[0]?.refusal ??
                "no window was retained")
              : null,
          // The watch runs over the film in windows. A window it refused left no record.
          windows: c.coverage.windows ?? null,
          failed: (c.coverage.windows_failed ?? []).map((w) => ({
            frames: w.frames,
            reason: REASONS[w.refusal] ?? w.refusal ?? w.reason ?? w.outcome,
          })),
          note: c.coverage.note ?? null,
        }
      : null,
    bySize: c.comparison?.by_scripted_height ?? null,
    // Unmoving things the detector kept calling a person, with how many boxes each drew.
    fixed: fixedSpots(c.comparison?.persistent_unmatched),
    // null means the detector did not run on this film.
    inferred: c.detections?.frames_inferred ?? null,
    skipped: c.detections?.frames_not_inferred ?? null,
    compared: c.comparison?.scripted_boxes ?? null,
    matched: c.comparison?.matched ?? null,
    recall: c.comparison?.recall ?? null,
    overlap: c.comparison?.mean_iou ?? null,
    extra: c.comparison?.unmatched_person_detections ?? null,
    tracks: c.tracks?.tracks?.length ?? 0,
  }));
  const pairs = native.associations.map((a) => ({
    cameras: a.cameras,
    ran: a.outcome !== "not_run",
    // Side of the ground cells positions were grouped into before matching, in metres.
    cell: a.cell_m ?? null,
    reason: a.reason ?? null,
    separate: candidates(a.separate_devices),
    shared: candidates(a.shared_render),
    published: !!a.publication,
    // The same recordings matched again on a coarser ground grid, as a preview only.
    coarser: a.coarser_grid ? { cell: a.coarser_grid.cell_m ?? null, ...candidates(a.coarser_grid) } : null,
  }));
  // Detector results grouped by how large the staged person appears, summed over the cameras.
  const sizes = BANDS.map(([key, label]) => {
    const rows = cameras.map((c) => c.bySize?.[key]).filter(Boolean);
    return { key, label, compared: rows.reduce((n, r) => n + r.scripted_boxes, 0), matched: rows.reduce((n, r) => n + r.matched, 0) };
  }).filter((band) => band.compared > 0);
  // A call the driver listed but never made has no outcome and is left out.
  const calls = native.agent.calls.filter((c) => c.outcome).map((c) => ({
    call: c.call,
    operation: c.operation,
    view: VIEWS[c.view] ?? c.view,
    outcome: c.outcome,
    error: c.error,
    reason: REASONS[c.error] ?? null,
    tokens: c.tokens || null,
    target: c.target_tokens ?? null,
    states: c.knowledge_states ?? {},
  }));
  const opened = native.agent.calls.find((c) => c.outcome === "ok" && c.situation);
  const s = opened?.situation;
  return {
    // The repository's HEAD when the driver ran. The driver does not record which commit the binaries were built from.
    commit: native.fss.repository_commit,
    version: native.fss.version,
    qualification: native.fss.qualification,
    model: native.fss.model,
    captureTime: native.fss.capture_time,
    settings: native.fss.settings,
    commands: native.fss.commands.length,
    refusals: native.fss.commands.filter((c) => c.refusal).length,
    seconds: native.seconds,
    // How a detector box is compared with a staged one: null when it is the rule the page words itself.
    rule: (() => {
      const rules = [...new Set(Object.values(native.cameras).map((c) => c.comparison?.rule).filter(Boolean))];
      return rules.length === 1 && KNOWN_RULE.test(rules[0]) ? null : rules.join(" ") || null;
    })(),
    cameras,
    sizes,
    pairs,
    gate: native.fss.settings?.distance_gate_m ?? 1.5,
    events: native.events.map((e) => ({
      id: e.id,
      kind: e.kind,
      cameras: e.cameras,
      t: e.t,
      ground: e.ground ?? null,
      // An event from two cameras carries the earlier observation time and the gap to the later one.
      times: e.time_difference_s != null ? [e.t, e.t + e.time_difference_s] : [e.t],
      retainedDistance: e.nearest_scripted_person?.distance_m ?? null,
      state: e.state,
      action: e.policy_action,
      evidence: e.evidence_class,
      verified: e.custody?.all_verified ?? null,
      objects: e.custody?.objects ?? null,
    })),
    fusion: {
      outcome: native.fusion.outcome ?? null,
      reason: native.fusion.reason ?? null,
      hypothesis: native.fusion.hypothesis,
      assumptions: native.fusion.assumptions,
      notObservable: native.fusion.not_observable,
      variants: (native.fusion.variants ?? []).map((v) => ({
        id: v.id,
        outcome: v.outcome,
        reason: v.reason ?? v.refusal ?? null,
        declaration: v.declaration,
        calibrated: v.calibrated_inputs,
        decision: v.decision,
        state: v.knowledge_state,
        millibans: v.posterior_log_odds_millibans,
        ppm: v.probability_ppm,
        clusters: v.supporting_clusters,
        reasons: v.reasons,
      })),
    },
    ledger: native.ledger,
    alert: native.agent.facts.alert ?? null,
    single: native.agent.facts.single_camera_alert ?? null,
    calls,
    briefing: s && {
      call: opened.call,
      view: VIEWS[opened.view] ?? opened.view,
      tokens: opened.tokens,
      target: opened.target_tokens,
      warnings: opened.warnings ?? [],
      salient: s.salient ?? [],
      unknowns: s.unknowns ?? [],
      notObservable: s.not_observable ?? [],
      coverage: s.coverage ?? null,
      attention: s.attention ?? [],
      debt: s.epistemic_debt ?? [],
      control: s.control ?? {},
      compression: s.compression ?? null,
    },
    // The driver's free-text notes are left out on purpose. In the published run one of them
    // says no absence is certified, which the tool's own reports contradict (see load.js).
  };
}
