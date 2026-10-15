// Native JavaScript test runner only; no npm install or frontend runtime dependency.
import test from 'node:test';
import assert from 'node:assert/strict';
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
