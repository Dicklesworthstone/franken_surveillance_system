import { MAX_BYTES, normalizeSnapshot, parseExactJson, human, shortDigest, tone, filterEvents, timeBounds, position, relativeTime, edgePage } from './model.js';

const $ = id => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };
const svgEl = (tag, attrs = {}, text) => { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v)); if (text !== undefined) n.textContent = text; return n; };
const btn = (text, cls, action) => { const b = el('button', cls, text); b.type = 'button'; b.addEventListener('click', action); return b; };
const badge = state => el('span', `badge ${tone(state)}`, human(state));
const empty = (title, detail) => { const d = el('div', 'empty-state'); d.append(el('strong', '', title), el('p', '', detail)); return d; };
const VIEWS = {
  overview: ['Overview', 'Clarity starts with evidence.', 'Your retained world, without the assumptions.'],
  events: ['Event explorer', 'Follow the evidence.', 'Every latest revision. Every unresolved question.'],
  graph: ['Evidence graph', 'See how the facts connect.', 'Explore declared relationships without inventing certainty.'],
  operations: ['Operations', 'Know what is still open.', 'Retained obligations, effects, and custody references. No write actions.'],
};
const GLYPHS = { perimeter_breach: '⌗', covert_approach: '⌁', sensor_tamper: '◈', unknown_presence: '◌', benign_routine: '◇', unclassified: '·' };
let data = null, selected = null, selectedEdge = null, view = 'overview', tab = 'summary';
let eventPage = 0, graphPage = 0, paused = false, fetching = false, controller = null, timer = null, toastTimer = null;
let graphBox = { x: 0, y: 0, width: 920, height: 500 };
let readAt = null;

function announce(text) { clearTimeout(toastTimer); $('toast').textContent = text; $('toast').hidden = false; toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3500); }
async function copy(text) {
  try { await navigator.clipboard.writeText(text); announce('Exact identity copied.'); }
  catch { announce('Clipboard access is unavailable. Select and copy the displayed value.'); }
}
function setConnection(text, state = '') {
  const node = $('connection-state'); node.className = `connection ${state}`;
  node.replaceChildren(el('span', 'status-dot'), el('span', '', text));
}
function switchView(next, focus = false) {
  if (!VIEWS[next]) return;
  view = next;
  for (const name of Object.keys(VIEWS)) $(`${name}-view`).hidden = name !== next;
  document.querySelectorAll('.nav-link').forEach(b => { b.classList.toggle('active', b.dataset.view === next); if (b.dataset.view === next) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  const [label, title, subtitle] = VIEWS[next];
  $('current-view').textContent = label; $('page-title').textContent = title; $('page-subtitle').textContent = subtitle;
  document.querySelector('.workspace-grid').classList.toggle('wide', next === 'operations');
  $('inspector').hidden = next === 'operations';
  if (data && next === 'graph') renderGraph();
  if (focus) $('main').focus({ preventScroll: true });
}
function select(id, reveal = false) {
  selected = id; selectedEdge = null; graphPage = 0; tab = 'summary'; graphBox = { x: 0, y: 0, width: 920, height: 500 };
  renderLists(); renderTimeline(); renderInspector(); renderGraph();
  if (reveal && matchMedia('(max-width:800px)').matches) $('inspector').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start' });
}
function current() { return data?.events.find(e => e.id === selected); }
function addOption(select, value, label) { const o = el('option', '', label); o.value = value; select.append(o); }
function fillSelect(id, values, allLabel) {
  const select = $(id), old = select.value; select.replaceChildren();
  if (allLabel) addOption(select, 'all', allLabel);
  for (const [value, label] of values) addOption(select, value, label);
  if ([...select.options].some(o => o.value === old)) select.value = old;
}
function renderFilters() {
  fillSelect('state-filter', [...new Set(data.events.map(e => e.state))].sort().map(s => [s, human(s)]), 'All states');
  fillSelect('zone-filter', [...new Set(data.events.flatMap(e => e.zones))].sort().map(s => [s, s]), 'All zones');
  fillSelect('graph-event', data.events.map(e => [e.id, `${human(e.kind)} · ${e.id}`]));
}
function renderMetrics() {
  const c = data.counts;
  const cards = [
    ['Retained events', c.events, 'Latest committed revisions', '≋', false],
    ['Completed imports', c.imports, 'References, not current availability', '◫', false],
    ['Open obligations', c.openObligations, c.openObligations ? 'Terminal proof still outstanding' : 'No retained open obligations', '⌁', c.openObligations > 0],
    ['Unresolved effects', c.indeterminateOperations, c.indeterminateOperations ? 'Outcome remains indeterminate' : 'No retained indeterminate effects', '◌', c.indeterminateOperations > 0],
  ];
  $('metrics').replaceChildren(...cards.map(([name, count, foot, symbol, warn]) => {
    const card = el('article', 'metric'), top = el('div', 'metric-top');
    top.append(el('span', '', name), el('span', 'metric-symbol', symbol));
    card.append(top, el('div', 'metric-value', String(count)), el('p', `metric-foot ${warn ? 'warning' : ''}`, foot));
    return card;
  }));
}
function eventRow(e) {
  const b = btn('', `event-row ${e.id === selected ? 'selected' : ''}`, () => select(e.id, true));
  b.setAttribute('aria-label', `Inspect ${human(e.kind)}, ${human(e.state)}, ${e.id}`);
  b.setAttribute('aria-pressed', String(e.id === selected));
  const glyph = el('span', `event-glyph ${tone(e.kind === 'sensor_tamper' ? e.kind : e.state)}`, GLYPHS[e.kind]); glyph.setAttribute('aria-hidden', 'true');
  const text = el('div'); text.append(el('div', 'event-name', human(e.kind)));
  const meta = el('div', 'event-meta');
  meta.append(el('span', '', e.zones.length ? e.zones.join(' · ') : 'No zone recorded'), el('span', '', `${e.edges.length} references`));
  text.append(meta);
  const right = el('div', 'event-right'); right.append(badge(e.state), el('span', 'event-time', relativeTime(e.start, timeBounds(data.events).start)));
  b.append(glyph, text, right); return b;
}
function renderLists() {
  if (!data) return;
  $('recent-events').replaceChildren(...(data.events.length ? data.events.slice(0, 6).map(eventRow) : [empty('No retained event revisions.', 'A quiet inventory is not proof that nothing happened.')]));
  const filtered = filterEvents(data.events, $('event-search').value, $('state-filter').value, $('zone-filter').value);
  const pages = Math.max(1, Math.ceil(filtered.length / 20)); eventPage = Math.min(eventPage, pages - 1);
  const rows = filtered.slice(eventPage * 20, (eventPage + 1) * 20);
  $('all-events').replaceChildren(...(rows.length ? rows.map(eventRow) : [empty('No events match this view.', 'Change the search or reset the filters. No records were deleted.')]));
  $('event-range').textContent = `${filtered.length ? eventPage * 20 + 1 : 0}–${Math.min((eventPage + 1) * 20, filtered.length)} of ${filtered.length} matching · ${data.events.length} retained`;
  $('events-prev').disabled = eventPage === 0; $('events-next').disabled = eventPage + 1 >= pages;
}
function renderTimeline() {
  if (!data) return;
  if (!data.events.length) { $('timeline').replaceChildren(empty('No intervals to visualize.', 'Only retained event time bounds belong on this timeline.')); return; }
  const allZones = [...new Set(data.events.flatMap(e => e.zones.length ? e.zones : ['Unassigned']))].sort();
  const zones = allZones.slice(0, 5); if (allZones.length > 5) zones.push(`Other ${allZones.length - 5} zones`);
  const width = 780, left = 138, plot = width - left - 20, height = zones.length * 37 + 51;
  const s = svgEl('svg', { viewBox: `0 0 ${width} ${height}`, role: 'group', 'aria-label': 'Latest retained event intervals. Coordinates are relative to the earliest interval; blank areas are not evidence of absence.' });
  const bounds = timeBounds(data.events);
  for (let i = 0; i <= 4; i++) {
    const x = left + i * plot / 4;
    s.append(svgEl('line', { x1: x, x2: x, y1: 10, y2: height - 32, class: 'svg-line' }));
    s.append(svgEl('text', { x, y: height - 10, 'text-anchor': i === 4 ? 'end' : 'start', class: 'svg-text' }, relativeTime(bounds.start + (bounds.end - bounds.start) * BigInt(i) / 4n, bounds.start)));
  }
  zones.forEach((z, i) => {
    s.append(svgEl('text', { x: 0, y: 26 + i * 37, class: 'svg-label' }, z.length > 21 ? z.slice(0, 19) + '…' : z));
    s.append(svgEl('line', { x1: left, x2: width - 20, y1: 23 + i * 37, y2: 23 + i * 37, class: 'svg-line' }));
  });
  for (const e of [...data.events].reverse()) {
    const lanes = new Set((e.zones.length ? e.zones : ['Unassigned']).map(z => { const i = zones.indexOf(z); return i < 0 ? zones.length - 1 : i; }));
    for (const lane of lanes) {
      const x = position(e.start, bounds, plot), end = position(e.end, bounds, plot);
      const rect = svgEl('rect', { x: left + Math.min(x, plot - 7), y: 16 + lane * 37, width: Math.max(7, end - x), height: 14, rx: 4, tabindex: 0, role: 'button', class: `interval ${e.kind === 'sensor_tamper' || e.state === 'indeterminate' ? 'amber' : ''} ${e.id === selected ? 'selected' : ''}`, 'aria-label': `${human(e.kind)}, ${e.id}, earliest ${e.start} ns, latest ${e.end} ns` });
      rect.append(svgEl('title', {}, `${e.id}\n${human(e.state)}\n[${e.start}, ${e.end}] ns\n${e.record.uncertaintyReason || 'No additional uncertainty reason recorded'}`));
      rect.addEventListener('click', () => select(e.id, true));
      rect.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); select(e.id, true); } });
      s.append(rect);
    }
  }
  $('timeline').replaceChildren(s);
}
function fact(dl, label, value, mono = false) {
  const row = el('div'); const dd = el('dd'); dd.append(el(mono ? 'code' : 'span', '', value)); row.append(el('dt', '', label), dd); dl.append(row);
}
function renderInspector() {
  if (!data) return;
  const e = current();
  if (!e) { $('inspector-content').replaceChildren(empty('An open book, not a black box.', 'Select a retained event to inspect its state, uncertainty, and exact source references.')); return; }
  const body = el('div', 'inspector-body');
  body.append(badge(e.state), el('h2', 'inspector-title', human(e.kind)), el('p', 'event-id mono', e.id));
  const tabs = el('div', 'inspector-tabs');
  for (const [id, title] of [['summary', 'Summary'], ['record', 'Canonical record']]) {
    const b = btn(title, '', () => { tab = id; renderInspector(); }); b.setAttribute('aria-pressed', String(tab === id)); tabs.append(b);
  }
  body.append(tabs);
  if (tab === 'record') {
    body.append(el('p', 'evidence-disclaimer', 'Unmodified canonical JSON from the retained revision. Full-width integers are preserved in this original text.'), el('pre', 'canonical-json', e.recordJson), btn('Copy canonical record', 'primary-button', () => copy(e.recordJson)));
  } else {
    if (e.record.uncertaintyReason || e.state === 'indeterminate') {
      const u = el('div', 'uncertainty'); u.append(el('strong', '', 'Uncertainty is part of the record.'), el('span', '', e.record.uncertaintyReason || 'This event remains indeterminate. Do not treat it as a confirmed physical conclusion.')); body.append(u);
    }
    const p = e.record.probability, probability = el('section', 'detail-section');
    probability.append(el('div', 'detail-title', 'Recorded probability interval'));
    const val = el('div', 'probability-value', `${p.lower.toFixed(2)} – ${p.upper.toFixed(2)}`); val.append(el('small', '', p.calibrationGeneration ? 'Generation recorded' : 'Uncalibrated')); probability.append(val);
    const bar = svgEl('svg', { viewBox: '0 0 256 22', class: 'probability-svg', role: 'img', 'aria-label': `Recorded interval ${p.lower} to ${p.upper}. ${p.calibrationGeneration ? 'Calibration generation is recorded.' : 'Uncalibrated; not a confidence guarantee.'}` });
    bar.append(svgEl('line', { x1: 3, x2: 253, y1: 11, y2: 11, class: 'prob-track' }), svgEl('line', { x1: 3 + p.lower * 250, x2: 3 + p.upper * 250, y1: 11, y2: 11, class: 'prob-range' }), svgEl('circle', { cx: 3 + p.lower * 250, cy: 11, r: 3, class: 'prob-dot' }), svgEl('circle', { cx: 3 + p.upper * 250, cy: 11, r: 3, class: 'prob-dot' }));
    probability.append(bar); body.append(probability);
    const facts = el('dl', 'detail-facts');
    fact(facts, 'Zones', e.zones.join(' · ') || 'Not recorded');
    fact(facts, 'Revision', `${e.record.revision} · ${e.revisions} retained revisions`);
    fact(facts, 'Earliest', `${e.start} ns`, true); fact(facts, 'Latest', `${e.end} ns`, true);
    fact(facts, 'Commit', String(e.sequence), true);
    if (p.calibrationGeneration) fact(facts, 'Calibration', p.calibrationGeneration, true);
    body.append(facts);
    const section = el('section', 'detail-section');
    section.append(el('div', 'detail-title', selectedEdge ? 'SELECTED EXACT REFERENCE' : `DECLARED REFERENCES · ${e.edges.length}`));
    const edges = selectedEdge ? [selectedEdge] : e.edges.slice(0, 3);
    for (const edge of edges) {
      const row = el('div', 'edge-row'), top = el('div', 'edge-top');
      top.append(el('span', 'mono', shortDigest(edge.digest)), badge(edge.relation));
      row.append(top, el('p', '', `${human(edge.class)} · ${edge.failureDomain || 'No domain recorded'}`));
      if (selectedEdge) { row.append(el('p', 'mono', edge.digest)); if (edge.capsuleDigest) row.append(el('p', 'mono', `Capsule ${edge.capsuleDigest}`)); if (edge.identityDigest) row.append(el('p', 'mono', `Identity ${edge.identityDigest}`)); }
      section.append(row);
    }
    if (!e.edges.length) section.append(el('p', 'evidence-disclaimer', 'No evidence references recorded.'));
    if (!selectedEdge && e.edges.length > 3) section.append(el('p', 'evidence-disclaimer', `Showing 3 of ${e.edges.length}. Open the graph for every relationship.`));
    section.append(el('p', 'evidence-disclaimer', 'References are declared by the event. This view does not hydrate sources or certify current availability.'));
    body.append(section, btn('Explore evidence graph ↗', 'primary-button', () => { switchView('graph', true); }));
  }
  const root = el('div', 'root-box'); root.append(el('p', 'tiny-label', 'RETAINED REVISION DIGEST'));
  const copyButton = btn(`${shortDigest(e.revisionDigest)}   Copy ↗`, 'mono', () => copy(e.revisionDigest)); copyButton.title = e.revisionDigest; root.append(copyButton);
  root.append(el('p', 'evidence-disclaimer mono', e.revisionDigest)); body.append(root);
  $('inspector-content').replaceChildren(body);
}
function applyGraphBox() { const s = $('graph').querySelector('svg'); if (s) s.setAttribute('viewBox', `${graphBox.x} ${graphBox.y} ${graphBox.width} ${graphBox.height}`); }
function zoom(factor) {
  const next = Math.max(300, Math.min(1840, graphBox.width * factor)), ratio = next / graphBox.width;
  graphBox = { x: graphBox.x + (graphBox.width - next) / 2, y: graphBox.y + (graphBox.height - graphBox.height * ratio) / 2, width: next, height: graphBox.height * ratio };
  applyGraphBox();
}
function renderGraph() {
  if (!data) return;
  const e = current();
  if (!e) { $('graph').replaceChildren(empty('No selected event.', 'Choose an event to explore its declared dependencies.')); $('graph-range').textContent = '0 declared references'; $('graph-prev').disabled = $('graph-next').disabled = true; return; }
  $('graph-event').value = e.id;
  fillSelect('relation-filter', [...new Set(e.edges.map(x => x.relation))].sort().map(r => [r, human(r)]), 'All relationships');
  const page = edgePage(e, $('relation-filter').value, graphPage); graphPage = page.page;
  const s = svgEl('svg', { viewBox: `${graphBox.x} ${graphBox.y} ${graphBox.width} ${graphBox.height}`, role: 'group', 'aria-label': `Declared evidence references for ${e.id}; ${page.all.length} matching edges. This is not a spatial or custody map.` });
  const rootX = 460, rootY = 250;
  const defs = svgEl('defs'), marker = svgEl('marker', { id: 'arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: 'auto-start-reverse' });
  marker.append(svgEl('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: 'var(--secondary)' })); defs.append(marker); s.append(defs);
  page.rows.forEach((edge, i) => {
    const left = i < 6, local = i % 6, count = left ? Math.min(6, page.rows.length) : page.rows.length - 6;
    const x = left ? 28 : 668, y = 250 - (count * 69 - 10) / 2 + local * 69;
    const sourceX = left ? x + 224 : x, sourceY = y + 29, targetX = left ? rootX - 98 : rootX + 98;
    const path = svgEl('path', { d: `M ${sourceX} ${sourceY} C ${(sourceX + targetX) / 2} ${sourceY}, ${(sourceX + targetX) / 2} ${rootY}, ${targetX} ${rootY}`, class: `graph-edge ${tone(edge.relation)}`, 'marker-end': 'url(#arrow)' });
    path.append(svgEl('title', {}, human(edge.relation))); s.append(path);
    const group = svgEl('g', { tabindex: 0, role: 'button', 'aria-label': `Inspect ${edge.relation} reference ${edge.digest}; domain ${edge.failureDomain || 'not recorded'}` });
    group.append(svgEl('rect', { x, y, width: 224, height: 58, rx: 9, class: 'graph-node' }));
    group.append(svgEl('text', { x: x + 13, y: y + 18, class: `graph-node-relation ${tone(edge.relation)}` }, human(edge.relation).toUpperCase()));
    group.append(svgEl('text', { x: x + 13, y: y + 34, class: 'graph-node-label' }, `${human(edge.class)} · ${shortDigest(edge.digest)}`));
    const domain = edge.failureDomain || 'Domain not recorded';
    group.append(svgEl('text', { x: x + 13, y: y + 47, class: 'graph-node-detail' }, domain.length > 32 ? domain.slice(0, 29) + '…' : domain));
    group.append(svgEl('title', {}, `${edge.digest}\n${edge.failureDomain}\n${edge.relation}: declared by ${e.id}. Source not hydrated.`));
    const choose = () => { selectedEdge = edge; tab = 'summary'; renderInspector(); if (matchMedia('(max-width:800px)').matches) $('inspector').scrollIntoView({ block: 'start' }); };
    group.addEventListener('click', choose); group.addEventListener('keydown', ev => { if (['Enter', ' '].includes(ev.key)) { ev.preventDefault(); choose(); } }); s.append(group);
  });
  s.append(svgEl('circle', { cx: rootX, cy: rootY, r: 123, fill: 'none', stroke: 'var(--line)', 'stroke-dasharray': '3 7', opacity: .65 }));
  s.append(svgEl('rect', { x: rootX - 98, y: rootY - 49, width: 196, height: 98, rx: 14, class: 'graph-root' }));
  s.append(svgEl('text', { x: rootX, y: rootY - 22, 'text-anchor': 'middle', class: 'graph-node-relation sage' }, 'RETAINED EVENT'));
  s.append(svgEl('text', { x: rootX, y: rootY + 1, 'text-anchor': 'middle', class: 'graph-node-label' }, human(e.kind)));
  s.append(svgEl('text', { x: rootX, y: rootY + 22, 'text-anchor': 'middle', class: 'graph-node-detail' }, `${human(e.state)} · rev ${e.record.revision}`));
  if (!page.rows.length) s.append(svgEl('text', { x: rootX, y: rootY + 167, 'text-anchor': 'middle', class: 'svg-label' }, 'No references match this relationship.'));
  let drag = null;
  s.addEventListener('pointerdown', ev => { if (ev.target !== s) return; drag = { x: ev.clientX, y: ev.clientY, box: { ...graphBox } }; s.setPointerCapture(ev.pointerId); });
  s.addEventListener('pointermove', ev => { if (!drag) return; const rect = s.getBoundingClientRect(); graphBox.x = drag.box.x - (ev.clientX - drag.x) * drag.box.width / rect.width; graphBox.y = drag.box.y - (ev.clientY - drag.y) * drag.box.height / rect.height; applyGraphBox(); });
  s.addEventListener('pointerup', () => { drag = null; }); s.addEventListener('pointercancel', () => { drag = null; });
  $('graph').replaceChildren(s);
  $('graph-range').textContent = `${page.all.length ? page.page * 12 + 1 : 0}–${Math.min((page.page + 1) * 12, page.all.length)} of ${page.all.length} matching · ${e.edges.length} declared references`;
  $('graph-prev').disabled = page.page === 0; $('graph-next').disabled = page.page + 1 >= page.pages;
}
function opsPanel(title, subtitle) { const panel = el('article', 'panel'), heading = el('div', 'panel-heading'), text = el('div'); text.append(el('h2', '', title), el('p', '', subtitle)); heading.append(text); panel.append(heading); const content = el('div', 'ops-content'); panel.append(content); return [panel, content]; }
function stateRow(name, value, warn = false) { const row = el('div', `state-row ${warn ? 'warning' : ''}`); row.append(el('span', '', name), el('strong', '', String(value))); return row; }
function renderOperations() {
  const grid = el('div', 'ops-grid');
  const [integrity, facts] = opsPanel('Snapshot integrity', 'What the native reader observed');
  facts.append(stateRow('Read-only doctor verdict', data.integrity.doctor), stateRow('Authority ledger tail', data.integrity.ledgerTailUncommitted ? 'Uncommitted tail' : 'No uncommitted tail', data.integrity.ledgerTailUncommitted), stateRow('Effect journal tail', data.integrity.effectTailUncommitted ? 'Uncommitted tail' : 'No uncommitted tail', data.integrity.effectTailUncommitted), stateRow('Effect journal present', data.integrity.effectJournalPresent ? 'Yes' : 'No'), stateRow('Files read', data.integrity.filesRead), stateRow('Bytes read', data.integrity.bytesRead), el('p', 'ops-note', 'Metadata readback is not a source-availability certificate. Journals are read at retained positions; no cross-journal ordering is inferred.'));
  grid.append(integrity);
  const [ops, states] = opsPanel('Effects & obligations', 'Transport acceptance is not terminal proof');
  states.append(el('h3', '', 'Operation states'));
  if (!data.operationStates.length) states.append(el('p', 'ops-note', 'No retained operation receipts.'));
  data.operationStates.forEach(v => states.append(stateRow(human(v.name), v.count, v.name === 'indeterminate')));
  states.append(el('h3', 'detail-section', 'Obligation states'));
  if (!data.obligationStates.length) states.append(el('p', 'ops-note', 'No retained obligations.'));
  data.obligationStates.forEach(v => states.append(stateRow(human(v.name), v.count, ['pending', 'indeterminate'].includes(v.name)))); grid.append(ops);
  const [imports, inventory] = opsPanel('Import inventory', 'Completed-import roots at the selected snapshot');
  inventory.append(el('p', 'import-count', `${data.imports.length} retained references · ${data.counts.deletions} committed deletion records`));
  const list = el('div', 'import-list');
  data.imports.forEach((d, i) => { const row = el('div', 'import-row'); row.append(el('span', '', String(i + 1).padStart(2, '0')), el('code', '', d)); list.append(row); });
  if (!data.imports.length) list.append(empty('No completed imports.', 'The viewer will never create an import or open a camera.'));
  inventory.append(list, el('p', 'ops-note', 'Deleted imports are excluded by the native reader. Remaining roots are references; their source bytes are not read by this view.')); grid.append(imports);
  const [families, counts] = opsPanel('Evidence families', 'Committed deltas, not independent observations');
  data.families.forEach(v => counts.append(stateRow(human(v.name), v.count)));
  if (!data.families.length) counts.append(el('p', 'ops-note', 'No committed evidence deltas.'));
  counts.append(el('p', 'ops-note', data.scope)); grid.append(families);
  $('operations').replaceChildren(grid);
}
function render() {
  $('site-name').textContent = data.site; $('site-name').title = data.site;
  $('site-description').textContent = data.demo ? 'Synthetic demonstration' : 'Retained deployment';
  $('event-count').textContent = String(data.events.length); $('anchor-short').textContent = shortDigest(data.ledgerRoot);
  $('demo-banner').hidden = !data.demo;
  if (!data.events.some(e => e.id === selected)) selected = data.events[0]?.id ?? null;
  selectedEdge = null;
  renderFilters(); renderMetrics(); renderTimeline(); renderLists(); renderInspector(); renderGraph(); renderOperations();
  const c = data.counts;
  $('coverage-description').textContent = `${c.coverageRecords + c.sourceCoverageRecords} retained coverage records. Coverage is not assessed by this metadata view. Missing events never establish absence; current camera health is not observed here.`;
  $('workspace').hidden = false; $('loading').hidden = true; $('error-panel').hidden = true;
  switchView(view);
}
async function readResponse(response) {
  if (!response.ok) throw new Error(`Snapshot request refused (${response.status}). Check the selected deployment, site, and native read bounds.`);
  if (!response.headers.get('content-type')?.startsWith('application/json')) throw new Error('Unexpected response type; snapshot was not accepted.');
  const length = response.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES)) throw new Error('Response exceeds the dashboard byte bound.');
  const reader = response.body.getReader(), chunks = []; let total = 0;
  try {
    while (true) { const { value, done } = await reader.read(); if (done) break; total += value.length; if (total > MAX_BYTES) throw new Error('Response exceeds the dashboard byte bound.'); chunks.push(value); }
  } catch (error) { await reader.cancel(); throw error; }
  finally { reader.releaseLock(); }
  const joined = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(joined);
}
async function refresh() {
  if (fetching || document.hidden) return;
  clearTimeout(timer); fetching = true; $('refresh').disabled = true; $('retry').disabled = true;
  setConnection('Reading snapshot'); controller = new AbortController();
  const timeout = setTimeout(() => controller?.abort(), 10000);
  let success = false;
  try {
    const response = await fetch('/api/snapshot', { headers: { 'X-FSS-Read': '1' }, cache: 'no-store', credentials: 'omit', signal: controller.signal });
    const candidate = normalizeSnapshot(parseExactJson(await readResponse(response)));
    data = candidate; readAt = new Date(); render(); success = true;
    setConnection(paused ? 'Paused · retained snapshot' : `Read at ${readAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`, paused ? 'paused' : '');
  } catch (error) {
    data = null; selected = null; selectedEdge = null; readAt = null; commandActions = [];
    $('workspace').hidden = true; $('loading').hidden = true; $('error-panel').hidden = false;
    // Remove, not merely hide, stale/private metadata after a failed read.
    for (const id of ['metrics', 'timeline', 'recent-events', 'all-events', 'inspector-content', 'graph', 'operations', 'command-results']) $(id).replaceChildren();
    for (const id of ['graph-event', 'zone-filter', 'state-filter']) $(id).replaceChildren();
    $('site-name').removeAttribute('title'); $('site-name').textContent = 'Snapshot unavailable'; $('event-count').textContent = '—'; $('anchor-short').textContent = '—';
    for (const id of ['coverage-description', 'event-range', 'graph-range']) $(id).textContent = '';
    $('error-message').textContent = error.name === 'AbortError' ? 'The bounded read timed out or the tab became inactive.' : error.message;
    setConnection('Snapshot unavailable', 'error');
  } finally {
    clearTimeout(timeout); controller = null; fetching = false; $('refresh').disabled = false; $('retry').disabled = false;
    // One in-flight request, no polling when hidden/paused, and no automatic failure retry loop.
    if (success && !paused && !document.hidden) timer = setTimeout(refresh, 15000);
  }
}
function setPaused() {
  paused = !paused; $('pause-toggle').setAttribute('aria-pressed', String(paused)); $('pause-toggle').textContent = paused ? 'Resume updates' : 'Pause updates'; $('paused-banner').hidden = !paused;
  clearTimeout(timer);
  if (paused) setConnection('Paused · retained snapshot', 'paused'); else refresh();
}
let commandIndex = 0, commandActions = [];
function renderCommands() {
  const q = $('command-search').value.toLocaleLowerCase();
  const actions = Object.entries(VIEWS).map(([id, [title]]) => ({ title, detail: 'View', run: () => switchView(id, true) }));
  actions.push({ title: 'Refresh snapshot', detail: 'Read only', run: refresh }, { title: 'Switch color theme', detail: 'Appearance', run: toggleTheme });
  for (const e of data?.events ?? []) actions.push({ title: `${human(e.kind)} · ${e.id}`, detail: human(e.state), run: () => { select(e.id); switchView('events', true); } });
  commandActions = actions.filter(a => `${a.title} ${a.detail}`.toLocaleLowerCase().includes(q)).slice(0, 12); commandIndex = 0;
  $('command-results').replaceChildren(...commandActions.map((a, index) => {
    const b = btn('', 'command-item', () => { $('command-dialog').close(); a.run(); });
    b.append(el('span', '', a.title), el('small', '', a.detail)); b.setAttribute('aria-selected', String(index === commandIndex)); return b;
  }));
  if (!commandActions.length) $('command-results').append(empty('No matching command or event.', 'Try a view name, lifecycle state, or event identifier.'));
}
function openCommands() { renderCommands(); if (!$('command-dialog').open) $('command-dialog').showModal(); $('command-search').focus(); }
function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; applyTheme(next);
  try { localStorage.setItem('fss-observatory-theme-v1', next); } catch { /* UI remains usable when browser storage is blocked. */ }
}
function applyTheme(theme) { document.documentElement.dataset.theme = theme; $('theme-toggle').setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`); $('theme-toggle').querySelector('span').textContent = `Switch to ${theme === 'dark' ? 'light' : 'dark'}`; }
try { const saved = localStorage.getItem('fss-observatory-theme-v1'); applyTheme(['dark', 'light'].includes(saved) ? saved : 'dark'); } catch { applyTheme('dark'); }
document.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view, true)));
$('theme-toggle').addEventListener('click', toggleTheme); $('refresh').addEventListener('click', refresh); $('retry').addEventListener('click', refresh); $('pause-toggle').addEventListener('click', setPaused);
$('copy-anchor').addEventListener('click', () => { if (data) copy(data.ledgerRoot); });
for (const id of ['event-search', 'state-filter', 'zone-filter']) $(id).addEventListener(id === 'event-search' ? 'input' : 'change', () => { eventPage = 0; renderLists(); });
$('clear-filters').addEventListener('click', () => { $('event-search').value = ''; $('state-filter').value = 'all'; $('zone-filter').value = 'all'; eventPage = 0; renderLists(); });
$('events-prev').addEventListener('click', () => { eventPage--; renderLists(); }); $('events-next').addEventListener('click', () => { eventPage++; renderLists(); });
$('graph-event').addEventListener('change', ev => select(ev.target.value)); $('relation-filter').addEventListener('change', () => { graphPage = 0; renderGraph(); });
$('graph-prev').addEventListener('click', () => { graphPage--; renderGraph(); }); $('graph-next').addEventListener('click', () => { graphPage++; renderGraph(); });
$('zoom-in').addEventListener('click', () => zoom(.8)); $('zoom-out').addEventListener('click', () => zoom(1.25)); $('zoom-fit').addEventListener('click', () => { graphBox = { x: 0, y: 0, width: 920, height: 500 }; applyGraphBox(); });
$('command-open').addEventListener('click', openCommands); $('command-close').addEventListener('click', () => $('command-dialog').close());
$('command-dialog').addEventListener('click', ev => { if (ev.target === $('command-dialog')) $('command-dialog').close(); });
$('command-search').addEventListener('input', renderCommands);
$('command-search').addEventListener('keydown', ev => {
  if (!commandActions.length) return;
  if (ev.key === 'Enter') { ev.preventDefault(); $('command-dialog').close(); commandActions[commandIndex].run(); }
  if (['ArrowDown', 'ArrowUp'].includes(ev.key)) { ev.preventDefault(); commandIndex = (commandIndex + (ev.key === 'ArrowDown' ? 1 : commandActions.length - 1)) % commandActions.length; [...$('command-results').children].forEach((b, i) => b.setAttribute('aria-selected', String(i === commandIndex))); $('command-results').children[commandIndex]?.scrollIntoView({ block: 'nearest' }); }
});
document.addEventListener('keydown', ev => {
  if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') { ev.preventDefault(); openCommands(); return; }
  if ($('command-dialog').open || ['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName) || ev.altKey || ev.ctrlKey || ev.metaKey) return;
  if (ev.key === '/') { ev.preventDefault(); switchView('events'); $('event-search').focus(); }
  if ('1234'.includes(ev.key) && ev.key.length === 1) switchView(Object.keys(VIEWS)[Number(ev.key) - 1], true);
});
document.addEventListener('visibilitychange', () => { clearTimeout(timer); if (document.hidden) { controller?.abort(); setConnection('Hidden tab · updates paused', 'paused'); } else if (!paused) refresh(); });
refresh();
