// Native JavaScript test runner only; no npm install or frontend runtime dependency.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runInNewContext } from 'node:vm';
import { readFile } from 'node:fs/promises';
const web = new URL('../crates/fss-cli/src/bin/fss-dashboard/web/', import.meta.url);
const source = await readFile(new URL('model.js', web), 'utf8');
const model = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const fixture = JSON.parse(await readFile(new URL('demo.json', web), 'utf8'));
const clone = () => structuredClone(fixture);
const mutateRecord = (raw, edit) => {
  const record = model.parseExactJson(raw.events[0].recordJson);
  edit(record);
  raw.events[0].recordJson = JSON.stringify(record);
};

test('explicit demonstration keeps original canonical text and exact nanoseconds', () => {
  const data = model.normalizeSnapshot(clone());
  assert.equal(data.demo, true);
  assert.equal(data.events.length, 9);
  assert.equal(data.events[0].start, 1789398468000000123n);
  assert.equal(data.events[0].end, 1789398482000000789n);
  assert.equal(data.events[0].recordJson, fixture.events[0].recordJson);
});
test('unsafe numeric tokens are preserved before the JSON parser can round', () => {
  const v = model.parseExactJson('{"wide":18446744073709551615,"signed":-170141183460469231731687303715884105728,"safe":9007199254740991,"fraction":0.125,"exponent":1e-6}');
  assert.equal(v.wide, '18446744073709551615');
  assert.equal(v.signed, '-170141183460469231731687303715884105728');
  assert.equal(v.safe, Number.MAX_SAFE_INTEGER);
  assert.equal(v.fraction, 0.125);
  assert.equal(v.exponent, 1e-6);
});
test('quoted strings, escaping, identifiers and markup are not rewritten', () => {
  const original = { name: '18446744073709551615', text: 'a "quoted 18446744073709551615" \\ tail', html: '<img onerror="42">', unicode: '雪\n\t' };
  assert.deepEqual(model.parseExactJson(JSON.stringify(original)), original);
});
test('bad JSON and oversized reports never become partial data', () => {
  for (const value of ['{', '{"a":01}', 'NaN', 'null trailing', ' '.repeat(model.MAX_BYTES + 1)]) assert.throws(() => model.parseExactJson(value));
});
test('native signed 128-bit timestamp boundaries are exact', () => {
  assert.equal(model.nanos(String(-(1n << 127n))), -(1n << 127n));
  assert.equal(model.nanos(String((1n << 127n) - 1n)), (1n << 127n) - 1n);
  for (const value of [String(1n << 127n), String(-(1n << 127n) - 1n), 9007199254740992, '01', '+1', '1.5', null]) assert.throws(() => model.nanos(value));
});
test('timeline scaling never converts absolute wide timestamps to floating point', () => {
  const start = (1n << 100n), bounds = { start, end: start + 10n };
  assert.equal(model.position(start + 1n, bounds), 100);
  assert.equal(model.position(start + 5n, bounds), 500);
  assert.equal(model.position(start - 1n, bounds), 0);
  assert.equal(model.position(start + 11n, bounds), 1000);
  assert.equal(model.position(start, { start, end: start }), 0);
});
test('relative labels make no UTC or coverage claim', () => {
  assert.equal(model.relativeTime(1789398468000000123n, 1789398468000000000n), 'T+123 ns');
  assert.equal(model.relativeTime(0n, 10n), 'T−10 ns');
  assert.equal(model.relativeTime(61100000000n, 0n), 'T+1m 1s');
});
test('search combines identity, kind, state, zone and declared failure domain', () => {
  const events = model.normalizeSnapshot(clone()).events;
  assert.equal(model.filterEvents(events, 'tamper').length, 1);
  assert.equal(model.filterEvents(events, '', 'witnessed').length, 3);
  assert.equal(model.filterEvents(events, '', 'witnessed', 'zone:courtyard').length, 1);
  assert.equal(model.filterEvents(events, 'shared uplink').length, 1);
  assert.equal(model.filterEvents(events, 'not-a-source').length, 0);
  assert.equal(events.length, 9);
});
test('all 256 references remain reachable through exact pages', () => {
  const event = { edges: Array.from({ length: 256 }, (_, i) => ({ digest: `reference:${i}`, relation: i % 2 ? 'supports' : 'contradicts' })) };
  const found = [];
  for (let p = 0; p < 22; p++) found.push(...model.edgePage(event, 'all', p).rows);
  assert.deepEqual(found, event.edges);
  assert.equal(model.edgePage(event, 'contradicts').all.length, 128);
  assert.equal(model.edgePage(event, 'all', 100).page, 21);
  assert.equal(model.edgePage({ edges: [] }).pages, 1);
});
test('an empty retained snapshot is not replaced by demo events', () => {
  const raw = clone(); raw.demo = false; raw.events = []; raw.imports = [];
  raw.counts.events = 0; raw.counts.imports = 0;
  const data = model.normalizeSnapshot(raw);
  assert.equal(data.demo, false); assert.equal(data.events.length, 0);
  assert.deepEqual(model.timeBounds(data.events), { start: 0n, end: 1n });
});
for (const [name, edit] of [
  ['unknown format', r => { r.format = 'other'; }],
  ['missing demo discriminator', r => { delete r.demo; }],
  ['missing site', r => { delete r.site; }],
  ['missing ledger root', r => { r.ledgerRoot = 'unknown'; }],
  ['incomplete event inventory', r => { r.events.pop(); }],
  ['incomplete import inventory', r => { r.imports.pop(); }],
  ['duplicate event identity', r => { r.events[1] = r.events[0]; }],
  ['too many events', r => { r.events = Array(257).fill(r.events[0]); r.counts.events = 257; }],
  ['missing uncertainty counter', r => { delete r.counts.indeterminateOperations; }],
  ['missing journal status', r => { delete r.integrity.effectTailUncommitted; }],
  ['unknown native state', r => mutateRecord(r, e => { e.state = 'safe'; })],
  ['unknown native relationship', r => mutateRecord(r, e => { e.evidence[0].relation = 'proved'; })],
  ['inverted event interval', r => mutateRecord(r, e => { e.timeInterval.earliestNs = e.timeInterval.latestNs + '0'; })],
  ['invalid probability', r => mutateRecord(r, e => { e.probability.lower = 1.1; })],
  ['too many references', r => mutateRecord(r, e => { e.evidence = Array(257).fill(e.evidence[0]); })],
]) {
  test(`${name} refuses instead of silently defaulting`, () => { const raw = clone(); edit(raw); assert.throws(() => model.normalizeSnapshot(raw)); });
}

const liveScript = (await readFile(new URL('live.js', web), 'utf8')).replace(
  "import { parseExactJson } from './model.js';", ''
);

// Drive the shipped controller with queued EventSource callbacks and a small DOM surface.
function cockpit() {
  const nodes = new Map(), streams = [], visibility = {}, lifecycle = {};
  const node = () => ({
    children: [], textContent: '', hidden: false, className: '',
    append(...items) { this.children.push(...items); },
    replaceChildren(...items) { this.children = items; },
    querySelector(tag) { return this.children.find(child => child.tagName === tag); },
    addEventListener(type, listener) { this[type] = listener; }
  });
  function get(id) {
    if (!nodes.has(id)) nodes.set(id, node());
    return nodes.get(id);
  }
  const document = {
    hidden: false, getElementById: get, createElement(tagName) { return { ...node(), tagName }; },
    addEventListener(type, listener) { visibility[type] = listener; }
  };
  class Source {
    static CLOSED = 2;
    constructor(url) {
      assert.equal(url, '/api/live/stream');
      streams.push(this);
    }
    addEventListener(type, listener) { this[type] = listener; }
    close() { this.readyState = Source.CLOSED; }
    deliver(data) { this.live_frame({ data }); }
  }
  const window = { addEventListener(type, listener) { lifecycle[type] = listener; } };
  runInNewContext(liveScript, { document, window, EventSource: Source, parseExactJson: model.parseExactJson });
  return { get, streams, document, visibility, lifecycle };
}

const frameJson = JSON.stringify({
  schema: 'fss.dashboard_live_frame.v1', site: 'test-site', read_only: true, daemon_live: true,
  situation: { anchor_commit_sequence: 'WIDE', coverage_summary: {}, attention_frontier: [], affordances: [] },
  cameras: [], events: [], obligations_and_holds: {notes: []}, storage_ring: {},
  agent_log: {recent_deltas: [], operator_workflows: []}
}).replace('"WIDE"', '9007199254740993');

function assertCleared(view) {
  for (const pane of ['cameras', 'situation', 'events', 'obligations', 'storage', 'agent']) {
    assert.equal(view.get(pane + '-body').children.length, 0, pane);
  }
  assert.equal(view.get('live-dot').className, 'dot');
  assert.equal(view.get('anchor-badge').textContent, 'anchor —');
}

test('cockpit clears on disconnect, recovers from the full stream frame, and preserves exact anchors', () => {
  const view = cockpit(), stream = view.streams[0];
  stream.deliver(frameJson);
  assert.equal(view.get('anchor-badge').textContent, 'seq 9007199254740993');
  assert.equal(view.get('agent-body').children.length, 1);
  stream.onerror();
  assertCleared(view);
  assert.match(view.get('site-label').textContent, /reconnecting/);
  stream.deliver(frameJson);
  assert.equal(view.get('live-dot').className, 'dot live');
  stream.close();
  stream.onerror();
  assertCleared(view);
  assert.equal(view.get('retry-live').hidden, false);
  view.get('retry-live').click();
  assert.equal(view.streams.length, 2);
  stream.deliver(frameJson);
  assertCleared(view);
});

test('hidden or invalid cockpit frames cannot leave camera or event state on screen', () => {
  const view = cockpit();
  view.streams[0].deliver(frameJson);
  view.document.hidden = true;
  view.visibility.visibilitychange();
  assertCleared(view);
  assert.equal(view.streams[0].readyState, 2);
  view.streams[0].deliver(frameJson);
  assertCleared(view);
  view.document.hidden = false;
  view.visibility.visibilitychange();
  view.lifecycle.pageshow();
  assert.equal(view.streams.length, 2);
  const next = view.streams[1];
  next.deliver(frameJson);
  next.deliver(frameJson.replace('"notes":[]', '"notes":null'));
  assertCleared(view);
  assert.equal(next.readyState, 2);
  assert.equal(view.get('retry-live').hidden, false);
  view.get('retry-live').click();
  view.streams[2].deliver('{"schema":"unknown"}');
  assertCleared(view);
  view.get('retry-live').click();
  view.streams[3].deliver(frameJson);
  view.lifecycle.pagehide();
  assertCleared(view);
});

test('all 64 admitted cockpit events remain inspectable across updates', () => {
  const view = cockpit(), frame = JSON.parse(frameJson);
  frame.events = Array.from({ length: 64 }, (_, index) => ({
    event_id: 'event:' + index, epistemic_classification: 'Observed', failure_domain_clusters: 0,
    fusion_summary: 'details unavailable', privacy_masked_handle: { handle_id: 'h:' + index, raw_media_exposed: false }
  }));
  const stream = view.streams[0], host = view.get('events-body');
  stream.deliver(JSON.stringify(frame));
  const more = host.querySelector('details');
  assert.equal(host.children.length, 13);
  assert.equal(more.children.length, 53);
  assert.match(more.children[0].textContent, /52 more · 64 events in this frame/);
  assert.equal(more.children[52].children[1].textContent, 'event:63 ');
  more.open = true;
  stream.deliver(JSON.stringify(frame));
  assert.equal(host.querySelector('details').open, true);
  frame.events.push(frame.events[0]);
  stream.deliver(JSON.stringify(frame));
  assertCleared(view);
});
