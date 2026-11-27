import { parseExactJson } from './model.js';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const fpsText = (milli) => `${(Number(milli || 0) / 1000).toFixed(1)}`;

function renderFrame(f) {
  if (f?.schema !== 'fss.dashboard_live_frame.v1' || f.read_only !== true ||
      typeof f.daemon_live !== 'boolean' || typeof f.site !== 'string') {
    throw new Error('Unsupported cockpit frame.');
  }
  $('live-dot').className = `dot ${f.daemon_live ? 'live' : ''}`;
  $('site-label').textContent = `${f.site} · ${f.daemon_live ? 'LIVE IPC' : 'OFFLINE MVCC'}`;
  $('mode-badge').textContent = f.read_only ? 'READ-ONLY' : 'MUTABLE';
  $('anchor-badge').textContent = `seq ${f.situation.anchor_commit_sequence}`;
  $('latency-badge').textContent = `deltas ${f.deltas_received} · max ${f.max_delta_latency_ms}ms`;

  // Pane 1: Camera Mesh Health
  const camHost = $('cameras-body');
  if (!f.cameras.length) {
    camHost.replaceChildren(el('p', '', 'No camera telemetry rows. Silence is not evidence of absence.'));
  } else {
    const tbl = el('table');
    const hdr = el('tr');
    for (const h of ['Camera', 'State', 'In FPS', 'Recon', 'Q', 'Drop', 'Coverage', 'Gaps']) hdr.append(el('th', '', h));
    tbl.append(hdr);
    for (const c of f.cameras) {
      const tr = el('tr');
      for (const v of [c.camera_id, c.state, fpsText(c.fps_in_milli), c.reconnect_count, c.queue_depth, c.dropped_frames, c.coverage_status, c.active_gaps]) {
        tr.append(el('td', '', String(v)));
      }
      tbl.append(tr);
    }
    camHost.replaceChildren(tbl);
  }

  // Pane 2: Active Situation & Attention Frontier
  const sit = f.situation;
  const sitHost = $('situation-body');
  const sitNodes = [
    el('div', 'row-card mono', `epistemic=${sit.epistemic_state} · covered=${sit.coverage_summary.covered_zones} stale=${sit.coverage_summary.stale_zones} not_obs=${sit.coverage_summary.not_observable_zones}`),
  ];
  for (const a of sit.attention_frontier) {
    const card = el('div', 'row-card');
    card.append(el('span', `tag ${a.priority === 'critical' ? 'crit' : 'warn'}`, a.priority), el('span', '', `${a.category}: ${a.summary}`));
    sitNodes.push(card);
  }
  const affCard = el('div', 'row-card');
  affCard.append(el('strong', '', 'Affordances: '), el('code', '', sit.affordances.map((a) => a.affordance_id).join(', ')));
  sitNodes.push(affCard);
  sitHost.replaceChildren(...sitNodes);

  // Pane 3: Corroborated Events & Milliban Fusion
  const evHost = $('events-body');
  if (!f.events.length) {
    evHost.replaceChildren(el('p', '', 'No committed events yet. Empty inventory never certifies physical absence.'));
  } else {
    evHost.replaceChildren(...f.events.slice(0, 12).map((e) => {
      const card = el('div', 'row-card');
      const tone = e.epistemic_classification === 'Corroborated' ? 'ok' : 'warn';
      card.append(
        el('span', `tag ${tone}`, e.epistemic_classification),
        el('strong', '', `${e.event_id} `),
        el('span', '', `clusters=${e.failure_domain_clusters || 'unknown'} · ${e.fusion_summary}`),
        el('div', '', `handle=${e.privacy_masked_handle.handle_id} · raw_media=${e.privacy_masked_handle.raw_media_exposed}`),
      );
      return card;
    }));
  }

  // Pane 4: Obligations, Effects & Holds
  const ob = f.obligations_and_holds;
  const obNodes = [
    el('div', 'row-card mono', `open_obligations=${ob.open_obligations} · indeterminate_effects=${ob.indeterminate_effects} · active_holds=${ob.active_holds} · privacy_masks=${ob.privacy_masks}`),
    ...ob.notes.map((n) => el('div', 'row-card', n)),
  ];
  $('obligations-body').replaceChildren(...obNodes);

  // Pane 5: Storage Ring & Compaction
  const st = f.storage_ring;
  $('storage-body').replaceChildren(
    el('div', 'row-card mono', `packs=${st.pack_count} (sealed=${st.sealed_pack_count}) · on_disk=${st.on_disk_mb} MB`),
    el('div', 'row-card mono', `ring=${st.ring_used_bytes}/${st.ring_cap_bytes} B (${st.watermark_percent}%) · pressure=${st.resource_pressure}`),
    el('div', 'row-card mono', `scrubber=${st.scrubber_status} · verified_objs=${st.scrub_verified_objects} · imports=${st.total_footage_imports}`),
  );

  // Pane 6: Agent Activity Log & Workflows
  const logNodes = [];
  for (const d of [...f.agent_log.recent_deltas].reverse().slice(0, 6)) {
    logNodes.push(el('div', 'row-card mono', `seq=${d.commit_sequence} [${d.delta_class}] ${d.summary}`));
  }
  for (const w of f.agent_log.operator_workflows) {
    const card = el('div', 'row-card');
    card.append(el('span', 'tag warn', `${w.action} (approval_digest)`), el('code', '', w.preview_command));
    logNodes.push(card);
  }
  $('agent-body').replaceChildren(...(logNodes.length ? logNodes : [el('p', '', 'No deltas yet.')]));
}

// The SSE endpoint sends a full frame upon every connection, including a reconnect.
let stream = null;
const panes = ['cameras', 'situation', 'events', 'obligations', 'storage', 'agent'];

function clearFrame(status, retry = false) {
  $('live-dot').className = 'dot';
  $('site-label').textContent = status;
  $('mode-badge').textContent = 'READ-ONLY';
  $('anchor-badge').textContent = 'anchor —';
  $('latency-badge').textContent = 'deltas —';
  $('retry-live').hidden = !retry;
  for (const pane of panes) $(pane + '-body').replaceChildren();
}

function stop() {
  stream?.close();
  stream = null;
}

function connect() {
  if (document.hidden || stream) return;
  clearFrame('Connecting…');
  const current = new EventSource('/api/live/stream');
  stream = current;
  current.addEventListener('live_frame', (event) => {
    if (current !== stream) return;
    try {
      renderFrame(parseExactJson(event.data));
      $('retry-live').hidden = true;
    } catch {
      stop();
      clearFrame('Frame could not be read', true);
    }
  });
  current.onerror = () => {
    if (current !== stream) return;
    if (current.readyState === EventSource.CLOSED) {
      stop();
      clearFrame('Stream closed', true);
    } else {
      clearFrame('Connection lost · reconnecting…');
    }
  };
}

function pause() {
  stop();
  clearFrame('Paused');
}

$('retry-live').addEventListener('click', connect);
document.addEventListener('visibilitychange', () => document.hidden ? pause() : connect());
window.addEventListener('pagehide', pause);
window.addEventListener('pageshow', connect);
if (document.hidden) pause();
else connect();
