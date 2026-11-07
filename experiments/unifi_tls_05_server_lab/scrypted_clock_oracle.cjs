'use strict';
// Isolated source-oracle check. Extract only the reference's time-sync case;
// this evaluates no module initialization and opens no network service.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])) {
    throw new Error('expected absolute path to reference controller source');
}
const source = fs.readFileSync(process.argv[2], 'utf8');
const marker = "case 'ubnt_avclient_timeSync':";
const start = source.indexOf(marker);
const end = source.indexOf('break;', start + marker.length);
if (start < 0 || end < 0 || source.indexOf(marker, start + marker.length) >= 0) {
    throw new Error('reference time-sync case is absent or ambiguous');
}
const body = source.slice(start + marker.length, end);
const onTimeSync = vm.runInNewContext(`(session, m) => { ${body} }`, { Date });
const sends = [];
const session = {
    mac: '001122AABBCC',
    socket: { destroyed: false, writableEnded: false },
    send: (name, payload, expected, responseTo) => {
        sends.push({ name, payload, expected, responseTo });
        return sends.length;
    },
};
for (const messageId of [100, 101, 102]) {
    onTimeSync(session, { messageId, inResponseTo: 0 });
}
assert.equal(sends.length, 3);
for (let i = 0; i < sends.length; i++) {
    assert.equal(sends[i].name, 'ubnt_avclient_timeSync');
    assert.equal(sends[i].responseTo, 100 + i);
    assert.equal(sends[i].expected, false);
    assert.equal(typeof sends[i].payload.t1, 'number');
    assert.equal(typeof sends[i].payload.t2, 'number');
}
console.log('reference_oracle=three_uncorrelated_requests_answered network=none camera=none');
