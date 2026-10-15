// Pure presentation model. No I/O, authority decisions, HTML interpretation or inferred coverage.
export const FORMAT = 'fss.operator_dashboard.v1';
export const MAX_BYTES = 4 * 1024 * 1024;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const STATES = new Set(['hypothesized', 'witnessed', 'corroborated', 'adjudicated', 'alert_delivered', 'resolved', 'indeterminate', 'rejected']);
const KINDS = new Set(['perimeter_breach', 'covert_approach', 'sensor_tamper', 'unknown_presence', 'benign_routine', 'unclassified']);
const RELATIONS = new Set(['derived_from', 'supports', 'contradicts', 'invalidates', 'supersedes', 'observed_after', 'required_by', 'explains', 'sensor_tamper', 'sensor_integrity_restoration']);

export function parseExactJson(text) {
  if (typeof text !== 'string' || text.length > MAX_BYTES) throw new Error('JSON exceeds the view bound.');
  // Match complete strings before numbers. Never alter quoted data; preserve unsafe integer
  // tokens as decimal strings BEFORE JSON.parse can round 64/128-bit times and identities.
  return JSON.parse(text.replace(/"(?:[^"\\]|\\.)*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/g, token => {
    if (token[0] === '"' || /[.eE]/.test(token)) return token;
    return Number.isSafeInteger(Number(token)) ? token : JSON.stringify(token);
  }));
}
function demand(ok, message) { if (!ok) throw new Error(message); }
function boundedText(value, max = 512) { return typeof value === 'string' && value.length <= max; }
function count(value) { return Number.isSafeInteger(value) && value >= 0; }
export function nanos(value) {
  demand((typeof value === 'string' && /^-?(0|[1-9]\d{0,38})$/.test(value)) || Number.isSafeInteger(value), 'Invalid exact timestamp.');
  const n = BigInt(value);
  demand(n >= -(1n << 127n) && n < (1n << 127n), 'Timestamp outside native range.');
  return n;
}
export function normalizeSnapshot(raw) {
  demand(raw && raw.format === FORMAT && typeof raw.demo === 'boolean', 'Unsupported dashboard snapshot.');
  demand(boundedText(raw.site, 256) && DIGEST.test(raw.ledgerRoot), 'Missing site or ledger identity.');
  demand(typeof raw.sequence === 'string' && /^\d{1,20}$/.test(raw.sequence), 'Invalid snapshot sequence.');
  demand(Array.isArray(raw.events) && raw.events.length <= 256, 'Event inventory exceeds view bounds.');
  demand(Array.isArray(raw.imports) && raw.imports.length <= 4096 && raw.imports.every(v => typeof v === 'string' && DIGEST.test(v)), 'Invalid import inventory.');
  demand(raw.counts && Object.values(raw.counts).every(count), 'Invalid counters.');
  for (const key of ['events', 'imports', 'openObligations', 'indeterminateOperations', 'coverageRecords', 'sourceCoverageRecords', 'deletions']) demand(count(raw.counts[key]), 'Missing counter.');
  demand(raw.counts.events === raw.events.length && raw.counts.imports === raw.imports.length, 'Incomplete inventory; refusing partial snapshot.');
  demand(raw.integrity && boundedText(raw.integrity.doctor), 'Missing integrity state.');
  for (const key of ['ledgerTailUncommitted', 'effectTailUncommitted', 'effectJournalPresent']) demand(typeof raw.integrity[key] === 'boolean', 'Missing journal status.');
  for (const key of ['filesRead', 'bytesRead']) demand(typeof raw.integrity[key] === 'string' && /^\d{1,20}$/.test(raw.integrity[key]), 'Missing read accounting.');
  demand(boundedText(raw.scope, 2048) && typeof raw.anchorJson === 'string', 'Missing projection scope.');
  parseExactJson(raw.anchorJson);
  nanos(raw.latestEvidenceNs);
  for (const key of ['families', 'operationStates', 'obligationStates']) {
    demand(Array.isArray(raw[key]) && raw[key].length <= 4096 && raw[key].every(v => boundedText(v.name) && count(v.count)), 'Invalid state inventory.');
  }
  const ids = new Set();
  const events = raw.events.map(item => {
    demand(item && DIGEST.test(item.eventRoot) && DIGEST.test(item.revisionDigest) && count(item.revisions) && item.revisions > 0, 'Missing event custody identity.');
    const record = parseExactJson(item.recordJson);
    demand(record.schema === 'fss.event_hypothesis.v1' && boundedText(record.eventId, 128) && !ids.has(record.eventId), 'Duplicate or unsupported event.');
    ids.add(record.eventId);
    demand(STATES.has(record.state) && KINDS.has(record.kind), 'Unknown event vocabulary; refresh requires an updated viewer.');
    const start = nanos(record.timeInterval?.earliestNs), end = nanos(record.timeInterval?.latestNs);
    demand(start <= end, 'Inverted capture interval.');
    demand(Array.isArray(record.zoneIds) && record.zoneIds.length <= 64 && record.zoneIds.every(z => boundedText(z, 64)), 'Invalid zone metadata.');
    demand(Array.isArray(record.evidence) && record.evidence.length <= 256, 'Evidence edge bound exceeded.');
    for (const edge of record.evidence) demand(edge && DIGEST.test(edge.digest) && RELATIONS.has(edge.relation) && boundedText(edge.failureDomain, 128) && boundedText(edge.class, 32), 'Invalid evidence edge.');
    const p = record.probability;
    demand(p && Number.isFinite(p.lower) && Number.isFinite(p.upper) && p.lower >= 0 && p.upper <= 1 && p.lower <= p.upper, 'Invalid probability interval.');
    return { ...item, record, id: record.eventId, start, end, state: record.state, kind: record.kind, zones: record.zoneIds, edges: record.evidence };
  });
  events.sort((a, b) => a.start === b.start ? a.id.localeCompare(b.id) : a.start > b.start ? -1 : 1);
  return { ...raw, events };
}
export function human(value) { return String(value ?? '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase()); }
export function shortDigest(value) { return typeof value === 'string' ? value.replace(/^sha256:/, '').slice(0, 10) + '…' : 'Not recorded'; }
export function tone(state) {
  if (['indeterminate', 'sensor_tamper', 'invalidates', 'contradicts'].includes(state)) return 'amber';
  if (['corroborated', 'verified', 'resolved', 'supports'].includes(state)) return 'sage';
  if (['rejected', 'failed', 'cancelled'].includes(state)) return 'muted';
  return 'blue';
}
export function filterEvents(events, query = '', state = 'all', zone = 'all') {
  const q = query.trim().toLocaleLowerCase();
  return events.filter(e => (state === 'all' || e.state === state) && (zone === 'all' || e.zones.includes(zone)) &&
    (!q || [e.id, human(e.kind), human(e.state), ...e.zones, ...e.edges.map(x => x.failureDomain)].some(x => x.toLocaleLowerCase().includes(q))));
}
export function timeBounds(events) {
  if (!events.length) return { start: 0n, end: 1n };
  return events.reduce((b, e) => ({ start: e.start < b.start ? e.start : b.start, end: e.end > b.end ? e.end : b.end }), { start: events[0].start, end: events[0].end });
}
export function position(n, bounds, width = 1000) {
  const span = bounds.end - bounds.start || 1n;
  const value = Number((n - bounds.start) * BigInt(width) / span);
  return Math.max(0, Math.min(width, value));
}
export function relativeTime(n, origin) {
  const d = n - origin;
  const sign = d < 0n ? '−' : '+';
  const a = d < 0n ? -d : d;
  if (a < 1000n) return `T${sign}${a} ns`;
  if (a < 1000000n) return `T${sign}${a / 1000n} µs`;
  if (a < 1000000000n) return `T${sign}${a / 1000000n} ms`;
  if (a < 60000000000n) return `T${sign}${a / 1000000000n}.${String((a % 1000000000n) / 100000000n)} s`;
  return `T${sign}${a / 60000000000n}m ${a % 60000000000n / 1000000000n}s`;
}
export function edgePage(event, relation = 'all', page = 0, size = 12) {
  const all = event.edges.filter(e => relation === 'all' || e.relation === relation);
  const pages = Math.max(1, Math.ceil(all.length / size));
  const current = Math.max(0, Math.min(page, pages - 1));
  return { all, rows: all.slice(current * size, (current + 1) * size), page: current, pages };
}
